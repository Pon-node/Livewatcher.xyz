/**
 * LiveWatch Backend - Cloudflare Worker
 *
 * Auth model: each browser generates a UUID (client_id) on first visit, stored
 * in localStorage. All subscription operations require that client_id. Users
 * can only see/modify their own subscriptions. No accounts, no passwords.
 *
 * Endpoints:
 *   POST   /subscriptions                  - Create (body: client_id, wallet, channel, ...)
 *   GET    /subscriptions?client_id=...    - List the caller's subscriptions
 *   DELETE /subscriptions/:id              - Remove (header: X-Client-Id)
 *   POST   /telegram/link                  - Begin Telegram linking (returns one-time code)
 *   GET    /telegram/poll/:code            - Poll for completion of Telegram linking
 *   POST   /telegram/webhook               - Telegram bot webhook
 *
 * Cron trigger: every 30 minutes — fetches latest state per subscription,
 * dispatches notifications via the appropriate channel.
 *
 * Bindings (set in wrangler.toml):
 *   KV: SUBS   (subscriptions storage)
 *   KV: SNAP   (state snapshots for change detection)
 *   KV: CODES  (Telegram linking codes - short TTL)
 *   SECRET: TELEGRAM_BOT_TOKEN
 *
 * Channels: telegram, email (Resend), discord (webhook)
 *   Secrets: TELEGRAM_BOT_TOKEN, RESEND_API_KEY
 */

const ALLOWED_CHANNELS = ["telegram", "email", "discord"];
const MAX_SUBS_PER_CLIENT = 50;
// All toggleable notification flags (used by the Telegram settings keyboard).
const NOTIFY_FLAGS = [
  "notify_reward_cut", "notify_fee_cut", "notify_missed_reward",
  "notify_claim_report", "notify_governance", "notify_weekly_digest", "notify_monthly_digest",
];

// Livepeer Treasury contract (TimelockController that holds the funds) on Arbitrum
const TREASURY_ADDR = "0xf82C1FF415F1fCf582554fDba790E27019c8E8C4";
const LPT_TOKEN_ADDR = "0x289ba1701C2F088cf0faf8B3705246331cB8A839";
// LivepeerGovernor (OpenZeppelin Governor) proxy on Arbitrum One — proposals + votes
const GOVERNOR_ADDR = "0xcFE4E2879B786C3aa075813F0E364bb5acCb6aa0";
// BondingManager proxy on Arbitrum One
const BONDING_MANAGER_ADDR = "0x35Bcf3c30594191d53231e4ff333e8a770453e40";
// RoundsManager proxy on Arbitrum One
const ROUNDS_MANAGER_ADDR = "0xdd6f56DcC28D3F5f27084381fE8Df634985cc39f";

// Governor ProposalCreated event topic0 (keccak of the canonical signature)
const PROPOSAL_CREATED_TOPIC = "0x7d84a6263ae0d98d3329bd7b46bb4e8d6f98cd35a7adb45c274c8b7fd5ebd5e0";
// How many recent L2 blocks to scan for new proposals each cron tick.
// Arbitrum produces ~4 blocks/s; 12000 blocks ≈ 50 min > the 30-min cron interval.
const GOV_SCAN_BLOCKS = 12000;
const ARB_RPCS = [
  "https://arbitrum-one-rpc.publicnode.com",
  "https://arbitrum.drpc.org",
  "https://arb1.arbitrum.io/rpc",
];

const ALLOWED_ORIGINS = ["https://livewatcher.xyz", "https://pon-node.github.io"];

function corsHeaders(requestOrigin) {
  const origin = ALLOWED_ORIGINS.includes(requestOrigin) ? requestOrigin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Client-Id, X-Tg-User-Id",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}
// Legacy alias used by json()/err() helpers — patched per-request in the fetch handler
let CORS_HEADERS = corsHeaders("https://livewatcher.xyz");

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}
function err(message, status = 400) { return json({ error: message }, status); }
function newId() { return crypto.randomUUID(); }
function newCode() { const arr = new Uint32Array(1); crypto.getRandomValues(arr); return String(10000000 + (arr[0] % 90000000)); }
function todayKey() { return new Date().toISOString().slice(0, 10); }

function isUuid(s) {
  return typeof s === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
}

// Escape characters that Telegram's legacy Markdown parser treats as entity
// markers. Any unbalanced _ * ` [ in user/external text (nicknames, orchestrator
// display names) makes Telegram reject the whole message with HTTP 400, which
// silently drops the notification. Apply to all dynamic text interpolated into
// Markdown messages. Wallet addresses are hex so they never need escaping.
function escapeMd(s) {
  return String(s == null ? "" : s).replace(/([_*`\[])/g, "\\$1");
}

// Verify Telegram Login Widget auth payload per
// https://core.telegram.org/widgets/login#checking-authorization
async function verifyTelegramAuth(env, auth) {
  if (!auth || !auth.hash || !auth.auth_date || !auth.id) return false;
  // Build data_check_string from all fields except `hash`, sorted alphabetically
  const fields = Object.keys(auth)
    .filter(k => k !== "hash")
    .sort()
    .map(k => `${k}=${auth[k]}`)
    .join("\n");
  // Secret key = SHA-256(bot_token)
  const enc = new TextEncoder();
  const tokenHash = await crypto.subtle.digest("SHA-256", enc.encode(env.TELEGRAM_BOT_TOKEN));
  const key = await crypto.subtle.importKey(
    "raw", tokenHash, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(fields));
  const sigHex = Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, "0")).join("");
  // Also reject auth payloads older than 1 day to prevent replay
  const ageSec = Math.floor(Date.now() / 1000) - Number(auth.auth_date);
  if (ageSec > 86400) return false;
  return sigHex === auth.hash;
}

// Generic eth_call against public Arbitrum RPCs with fallback
async function ethCall(to, data) {
  for (const rpcUrl of ARB_RPCS) {
    try {
      const res = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0", id: 1, method: "eth_call",
          params: [{ to, data }, "latest"],
        }),
      });
      if (!res.ok) continue;
      const result = await res.json();
      if (result.error || !result.result) continue;
      return result.result; // hex string
    } catch (e) { console.warn(`RPC ${rpcUrl} failed:`, e.message); }
  }
  return null;
}

// ERC20 balanceOf via public Arbitrum RPC
async function fetchTreasuryBalance() {
  const data = "0x70a08231" + TREASURY_ADDR.toLowerCase().replace("0x", "").padStart(64, "0");
  const hex = await ethCall(LPT_TOKEN_ADDR, data);
  if (!hex) return null;
  return Number(BigInt(hex)) / 1e18;
}

// BondingManager.getTranscoder(address) -> first field is lastRewardRound
// selector for getTranscoder(address) = 0x1944cb05
async function getLastRewardRound(orchestrator) {
  const data = "0x1944cb05" + orchestrator.toLowerCase().replace("0x", "").padStart(64, "0");
  const hex = await ethCall(BONDING_MANAGER_ADDR, data);
  if (!hex) return null;
  // Response is multiple 32-byte fields; first uint256 is lastRewardRound
  const cleaned = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (cleaned.length < 64) return null;
  const firstWord = "0x" + cleaned.slice(0, 64);
  try { return Number(BigInt(firstWord)); }
  catch { return null; }
}

// RoundsManager.currentRound() -> uint256
// selector for currentRound() = 0x8a19c8bc
async function getCurrentRound() {
  const hex = await ethCall(ROUNDS_MANAGER_ADDR, "0x8a19c8bc");
  if (!hex) return null;
  try { return Number(BigInt(hex)); }
  catch { return null; }
}

// RoundsManager.currentRoundStartBlock() -> uint256
// selector for currentRoundStartBlock() = 0x8807f36e
async function getCurrentRoundStartBlock() {
  const hex = await ethCall(ROUNDS_MANAGER_ADDR, "0x8807f36e");
  if (!hex) return null;
  try { return Number(BigInt(hex)); }
  catch { return null; }
}

// ─── Governance (LivepeerGovernor, on-chain) ─────────────────────────────────
// eth_blockNumber -> latest L2 block number
async function getBlockNumber() {
  for (const rpcUrl of ARB_RPCS) {
    try {
      const res = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
      });
      if (!res.ok) continue;
      const j = await res.json();
      if (j.result) return Number(BigInt(j.result));
    } catch (e) { console.warn(`blockNumber ${rpcUrl} failed:`, e.message); }
  }
  return null;
}

// eth_getLogs for one address+topic over a block range, with RPC fallback.
async function ethGetLogs(address, topic0, fromBlock, toBlock) {
  const params = [{
    address,
    topics: [topic0],
    fromBlock: "0x" + Math.max(0, fromBlock).toString(16),
    toBlock: "0x" + toBlock.toString(16),
  }];
  for (const rpcUrl of ARB_RPCS) {
    try {
      const res = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getLogs", params }),
      });
      if (!res.ok) continue;
      const j = await res.json();
      if (j.error || !Array.isArray(j.result)) continue;
      return j.result;
    } catch (e) { console.warn(`getLogs ${rpcUrl} failed:`, e.message); }
  }
  return null;
}

// Read the i-th 32-byte word (as a hex string with 0x) from ABI-encoded data.
function abiWord(data, i) {
  const hex = data.startsWith("0x") ? data.slice(2) : data;
  return "0x" + hex.slice(i * 64, (i + 1) * 64);
}

// Pad a decimal proposalId (BigInt) into a 32-byte hex argument (no 0x).
function pidArg(pidBig) {
  return pidBig.toString(16).padStart(64, "0");
}

// Governor.state(uint256) -> enum (0 Pending,1 Active,2 Canceled,3 Defeated,
// 4 Succeeded,5 Queued,6 Expired,7 Executed). selector 0x3e4f49e6
async function getProposalState(pidBig) {
  const hex = await ethCall(GOVERNOR_ADDR, "0x3e4f49e6" + pidArg(pidBig));
  if (!hex) return null;
  try { return Number(BigInt(hex)); }
  catch { return null; }
}

// Governor.hasVoted(uint256,address) -> bool. selector 0x43859632
async function hasVoted(pidBig, account) {
  const arg = pidArg(pidBig) + account.toLowerCase().replace("0x", "").padStart(64, "0");
  const hex = await ethCall(GOVERNOR_ADDR, "0x43859632" + arg);
  if (!hex) return null;
  try { return BigInt(hex) === 1n; }
  catch { return null; }
}

// Governor.proposalDeadline(uint256) -> round number (Livepeer clock = rounds).
// selector 0xc01f9e37
async function getProposalDeadline(pidBig) {
  const hex = await ethCall(GOVERNOR_ADDR, "0xc01f9e37" + pidArg(pidBig));
  if (!hex) return null;
  try { return Number(BigInt(hex)); }
  catch { return null; }
}

// Scan recent blocks for ProposalCreated logs, merge into a persistent known-list
// in KV (gov:known), then return the proposals that are currently Active.
// Cached per-tick under gov:active so all subs in one cron reuse the result.
async function getActiveProposals(env) {
  // Per-tick cache (short TTL well under the 30-min cron interval)
  const cached = await env.SUBS.get("gov:active", "json");
  if (cached && Date.now() - cached.fetched_at < 10 * 60 * 1000) return cached.proposals;

  const latest = await getBlockNumber();
  if (latest == null) return [];

  // Discover new proposals from recent logs and merge into the known list.
  const known = (await env.SUBS.get("gov:known", "json")) || {};
  const logs = await ethGetLogs(GOVERNOR_ADDR, PROPOSAL_CREATED_TOPIC, latest - GOV_SCAN_BLOCKS, latest);
  if (logs) {
    for (const log of logs) {
      try {
        // ProposalCreated params are all non-indexed; data holds them inline.
        // word0 = proposalId, word6 = voteStart, word7 = voteEnd (rounds).
        const pid = BigInt(abiWord(log.data, 0)).toString();
        const voteEnd = Number(BigInt(abiWord(log.data, 7)));
        if (!known[pid]) known[pid] = { id: pid, voteEnd, seen_at: Date.now() };
      } catch (e) { console.warn("ProposalCreated decode failed:", e.message); }
    }
  }

  // Check on-chain state for each known proposal; keep Active ones, prune the
  // terminal ones (Canceled/Defeated/Expired/Executed) so the list stays small.
  const active = [];
  const pruned = {};
  for (const pid of Object.keys(known)) {
    const state = await getProposalState(BigInt(pid));
    if (state == null) { pruned[pid] = known[pid]; continue; } // RPC hiccup — keep, retry later
    if (state === 1) active.push(known[pid]);                  // Active
    if (state === 0 || state === 1 || state === 4 || state === 5) pruned[pid] = known[pid]; // keep non-terminal
  }
  await env.SUBS.put("gov:known", JSON.stringify(pruned));
  await env.SUBS.put("gov:active", JSON.stringify({ proposals: active, fetched_at: Date.now() }), { expirationTtl: 1800 });
  return active;
}

// ─── Livepeer API ────────────────────────────────────────────────────────────
async function lp(env, path, params = {}) {
  const qs = Object.entries(params)
    .filter(([_, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");
  const url = `${env.LIVEPEER_API_BASE}${path}${qs ? "?" + qs : ""}`;
  const res = await fetch(url, { cf: { cacheTtl: 60 } });
  if (!res.ok) throw new Error(`LP ${res.status}: ${path}`);
  return res.json();
}

// ─── Channels ────────────────────────────────────────────────────────────────
async function sendTelegram(env, chatId, text, opts = {}) {
  const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`;
  const body = {
    chat_id: chatId, text, parse_mode: "Markdown", disable_web_page_preview: true,
  };
  if (opts.reply_markup) body.reply_markup = opts.reply_markup;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) console.warn(`Telegram send failed: ${res.status} ${await res.text()}`);
  return res.ok;
}

async function sendEmail(env, toEmail, subject, text) {
  if (!env.RESEND_API_KEY) { console.warn("RESEND_API_KEY not set"); return false; }
  const safeHtml = text
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\n/g, "<br>");
  const html = `<!DOCTYPE html><html><body style="background:#050a0e;color:#e8f4f0;font-family:monospace;padding:24px;max-width:600px">
<p style="font-size:16px;font-weight:700;color:#00e5a0">${subject.replace(/&/g,"&amp;").replace(/</g,"&lt;")}</p>
<div style="font-size:14px;line-height:1.7">${safeHtml}</div>
<hr style="border:none;border-top:1px solid #1a2830;margin:24px 0">
<p style="font-size:11px;color:#4a7a8a">LiveWatch &middot; <a href="https://livewatcher.xyz" style="color:#00b8ff">livewatcher.xyz</a></p>
</body></html>`;
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${env.RESEND_API_KEY}` },
    body: JSON.stringify({ from: "LiveWatch <alerts@livewatcher.xyz>", to: [toEmail], subject, html }),
  });
  if (!res.ok) console.warn(`Email send failed: ${res.status} ${await res.text()}`);
  return res.ok;
}

async function sendDiscord(env, webhookUrl, title, message) {
  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      embeds: [{
        title,
        description: message,
        color: 0x00e5a0,
        footer: { text: "LiveWatch · livewatcher.xyz" },
        timestamp: new Date().toISOString(),
      }],
    }),
  });
  if (!res.ok) console.warn(`Discord webhook failed: ${res.status} ${await res.text()}`);
  return res.ok;
}

async function sendDiscordDM(env, userId, title, message) {
  if (!env.DISCORD_BOT_TOKEN) { console.warn("DISCORD_BOT_TOKEN not set"); return false; }
  const headers = { "Authorization": `Bot ${env.DISCORD_BOT_TOKEN}`, "Content-Type": "application/json" };
  // Open DM channel
  const dmRes = await fetch("https://discord.com/api/v10/users/@me/channels", {
    method: "POST", headers,
    body: JSON.stringify({ recipient_id: String(userId) }),
  });
  if (!dmRes.ok) { console.warn(`Discord DM channel create failed: ${dmRes.status} ${await dmRes.text()}`); return false; }
  const { id: channelId } = await dmRes.json();
  // Send message
  const msgRes = await fetch(`https://discord.com/api/v10/channels/${channelId}/messages`, {
    method: "POST", headers,
    body: JSON.stringify({
      embeds: [{
        title,
        description: message,
        color: 0x00e5a0,
        footer: { text: "LiveWatch · livewatcher.xyz" },
        timestamp: new Date().toISOString(),
      }],
    }),
  });
  if (!msgRes.ok) console.warn(`Discord DM send failed: ${msgRes.status} ${await msgRes.text()}`);
  return msgRes.ok;
}

async function editTelegram(env, chatId, messageId, text, replyMarkup) {
  const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/editMessageText`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId, message_id: messageId, text,
      parse_mode: "Markdown", disable_web_page_preview: true,
      reply_markup: replyMarkup,
    }),
  });
  if (!res.ok) console.warn(`Telegram edit failed: ${res.status} ${await res.text()}`);
  return res.ok;
}

async function answerCallback(env, callbackQueryId, text) {
  await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ callback_query_id: callbackQueryId, text: text || "" }),
  });
}

// Find subs belonging to the Telegram user (via tg_user_id OR fallback to chat_id)
async function findUserSubs(env, tgUserId, chatId) {
  const all = await listAllSubs(env);
  return all.filter(s => {
    if (tgUserId && String(s.tg_user_id) === String(tgUserId)) return true;
    if (chatId && String(s.telegram_chat_id) === String(chatId)) return true;
    return false;
  }).sort((a, b) => a.created_at - b.created_at);
}

// Resolve nickname for display
async function resolveNickname(env, sub) {
  const scope = sub.tg_user_id ? `tg:${sub.tg_user_id}` : `client:${sub.client_id}`;
  try { return await env.SUBS.get(`nick:${scope}:${sub.wallet}`); }
  catch { return null; }
}

function formatSubLine(sub, idx, nickname) {
  const safeNick = nickname ? escapeMd(nickname) : null;
  const label = safeNick ? `*${safeNick}* (\`${sub.wallet.slice(0, 8)}…${sub.wallet.slice(-4)}\`)` : `\`${sub.wallet.slice(0, 8)}…${sub.wallet.slice(-4)}\``;
  const flags = [];
  if (sub.notify_reward_cut) flags.push("RC");
  if (sub.notify_fee_cut) flags.push("FC");
  if (sub.notify_missed_reward) flags.push("MR");
  if (sub.notify_claim_report) flags.push("CR");
  if (sub.notify_governance !== false) flags.push("GV");
  if (sub.notify_weekly_digest) flags.push("WD");
  if (sub.notify_monthly_digest) flags.push("MD");
  return `*${idx + 1}.* ${label}\n   _${flags.join(" · ") || "no alerts"}_`;
}

function settingsKeyboard(sub) {
  const tick = (on) => on ? "✅" : "⬜";
  return {
    inline_keyboard: [
      [{ text: `${tick(sub.notify_reward_cut)} Reward cut changes`, callback_data: `toggle:${sub.id}:notify_reward_cut` }],
      [{ text: `${tick(sub.notify_fee_cut)} Fee cut changes`, callback_data: `toggle:${sub.id}:notify_fee_cut` }],
      [{ text: `${tick(sub.notify_missed_reward)} Missed rewards`, callback_data: `toggle:${sub.id}:notify_missed_reward` }],
      [{ text: `${tick(sub.notify_claim_report)} Claim reports`, callback_data: `toggle:${sub.id}:notify_claim_report` }],
      [{ text: `${tick(sub.notify_governance !== false)} Treasury proposal votes`, callback_data: `toggle:${sub.id}:notify_governance` }],
      [{ text: `${tick(sub.notify_weekly_digest)} Weekly earnings digest`, callback_data: `toggle:${sub.id}:notify_weekly_digest` }],
      [{ text: `${tick(sub.notify_monthly_digest)} Monthly earnings digest`, callback_data: `toggle:${sub.id}:notify_monthly_digest` }],
      [{ text: "✕ Close", callback_data: `close` }],
    ],
  };
}

const BOT_HELP_TEXT = `*LiveWatch Bot Commands*

\`/list\` — Show your subscriptions
\`/add 0x…\` — Add a wallet to monitor
\`/remove N\` — Remove subscription #N
\`/nickname N name\` — Set nickname for #N (or \`clear\`)
\`/settings N\` — Toggle alert types for #N
\`/help\` — Show this message

_Tip: Get your subscription numbers from /list._`;

// Future: sendDiscord(env, sub, title, message) — bot DM via Discord API

async function dispatch(env, sub, title, message) {
  // Resolve nickname from KV (set via POST /nicknames). Scope: client or tg_user.
  let nickname = sub.nickname || null;
  if (!nickname) {
    try {
      const scope = sub.tg_user_id ? `tg:${sub.tg_user_id}` : `client:${sub.client_id}`;
      nickname = await env.SUBS.get(`nick:${scope}:${sub.wallet}`);
    } catch {}
  }
  const walletLabel = nickname ? `*${escapeMd(nickname)}* (\`${sub.wallet}\`)` : `\`${sub.wallet}\``;
  const text = `*${title}*\n\n${message}\n\n_Wallet: ${walletLabel}_`;
  if (sub.channel === "telegram" && sub.telegram_chat_id) {
    return sendTelegram(env, sub.telegram_chat_id, text);
  }
  if (sub.channel === "email" && sub.email_address) {
    return sendEmail(env, sub.email_address, title, text);
  }
  if (sub.channel === "discord") {
    if (sub.discord_user_id) return sendDiscordDM(env, sub.discord_user_id, title, text);
    if (sub.discord_webhook_url) return sendDiscord(env, sub.discord_webhook_url, title, text);
  }
  return false;
}

// ─── KV helpers ──────────────────────────────────────────────────────────────
async function listSubsByClient(env, clientId) {
  const list = await env.SUBS.list({ prefix: `client:${clientId}:` });
  const subs = [];
  for (const k of list.keys) {
    const id = k.name.split(":").pop();
    const sub = await env.SUBS.get(`sub:${id}`, "json");
    if (sub) subs.push(sub);
  }
  return subs.sort((a, b) => b.created_at - a.created_at);
}

async function listAllSubs(env) {
  const subs = [];
  let cursor;
  do {
    const list = await env.SUBS.list({ prefix: "sub:", cursor });
    for (const k of list.keys) {
      const sub = await env.SUBS.get(k.name, "json");
      if (sub) subs.push(sub);
    }
    cursor = list.list_complete ? null : list.cursor;
  } while (cursor);
  return subs;
}

async function saveSub(env, sub) {
  await env.SUBS.put(`sub:${sub.id}`, JSON.stringify(sub));
  await env.SUBS.put(`client:${sub.client_id}:${sub.id}`, "1");
}

async function deleteSub(env, sub) {
  await env.SUBS.delete(`sub:${sub.id}`);
  await env.SUBS.delete(`client:${sub.client_id}:${sub.id}`);
  await env.SNAP.delete(`snap:${sub.id}`);
}

// ─── Change detection ────────────────────────────────────────────────────────
// Returns { events, snap }. Each event may carry an onSent() callback that
// advances the relevant snapshot state — called by the dispatcher ONLY after the
// notification was delivered successfully, so a transient send failure is retried
// next tick instead of being silently lost. `snap` is persisted by the caller
// after the dispatch loop (or skipped entirely if null, e.g. on API error).
async function checkSubscription(env, sub, gov = {}) {
  const events = [];
  const wallet = sub.wallet.toLowerCase();

  try {
    const del = await lp(env, `/delegators/${wallet}`);
    if (!del.delegations || del.delegations.length === 0) return { events, snap: null };
    // Pick the delegation with the most recent as_of_block (the active one)
    const activeDelegation = [...del.delegations].sort((a, b) =>
      Number(b.as_of_block) - Number(a.as_of_block)
    )[0];
    const orchAddr = activeDelegation.delegate_address;

    // Fetch each endpoint independently so one failure doesn't kill all checks
    const [orch, cutsRes, stakeRes] = await Promise.all([
      lp(env, `/orchestrators/${orchAddr}`),
      lp(env, `/orchestrators/${orchAddr}/cuts-history`).catch(() => ({ data: [] })),
      lp(env, `/orchestrators/${orchAddr}/stake-history`).catch(() => ({ data: [] })),
    ]);

    // Markdown-safe label for the orchestrator, reused everywhere below.
    const orchLabel = escapeMd(orch.display_name || orchAddr.slice(0, 10));

    // cuts-history is sorted ascending (oldest first); newest cut is the last element
    const cuts = cutsRes.data || [];
    const latestCut = cuts.length > 0 ? cuts[cuts.length - 1] : null;
    const stakes = stakeRes.data || [];
    const prevSnap = (await env.SNAP.get(`snap:${sub.id}`, "json")) || {};

    // Snapshot we will persist. Carry prev state forward; advance display fields
    // unconditionally, and gating fields only via onSent (on successful send).
    const snap = {
      ...prevSnap,
      orchestrator_address: orchAddr,
      latest_round_seen: stakes[stakes.length - 1]?.round,
      checked_at: Date.now(),
    };

    // Build block→round lookup from stake history (sorted ascending by block)
    const sortedStakes = [...stakes].sort((a, b) => Number(a.block_number) - Number(b.block_number));
    const blockToRound = (blockNum) => {
      const bn = Number(blockNum);
      let round = null;
      for (const s of sortedStakes) {
        if (Number(s.block_number) <= bn) round = s.round;
        else break;
      }
      return round;
    };

    // ── Cut changes ──
    // Iterate every cut event newer than the stored baseline so multiple changes
    // within one cron window are all reported (not just the latest).
    const cutEvents = [];
    if (latestCut) {
      const haveBaseline = !!prevSnap.latest_cut_event_id;
      let newCuts = [];
      if (haveBaseline) {
        const idx = cuts.findIndex(c => c.event_id === prevSnap.latest_cut_event_id);
        newCuts = idx >= 0 ? cuts.slice(idx + 1) : [latestCut];
      }
      let prevReward = prevSnap.reward_cut_percent;
      let prevFee = prevSnap.fee_cut_percent;
      for (const c of newCuts) {
        // Advance baseline (gating) state to THIS cut once its alert is delivered.
        const onSent = () => {
          snap.latest_cut_event_id = c.event_id;
          snap.reward_cut_percent = c.reward_cut_percent;
          snap.fee_cut_percent = c.fee_cut_percent;
        };
        if (sub.notify_reward_cut && prevReward != null && c.reward_cut_percent !== prevReward) {
          const up = Number(c.reward_cut_percent) > Number(prevReward);
          const rcRound = blockToRound(c.block_number);
          cutEvents.push({
            title: `${up ? "⚠️" : "✅"} Reward Cut ${up ? "Increased" : "Decreased"}`,
            message: `Orchestrator \`${orchLabel}\` changed reward cut from **${Number(prevReward).toFixed(2)}%** → **${Number(c.reward_cut_percent).toFixed(2)}%**` + (rcRound ? ` (round **${rcRound}**)` : ""),
            onSent,
          });
        }
        if (sub.notify_fee_cut && prevFee != null && c.fee_cut_percent !== prevFee) {
          const up = Number(c.fee_cut_percent) > Number(prevFee);
          const fcRound = blockToRound(c.block_number);
          cutEvents.push({
            title: `${up ? "⚠️" : "✅"} Fee Cut ${up ? "Increased" : "Decreased"}`,
            message: `Orchestrator \`${orchLabel}\` changed fee cut from **${Number(prevFee).toFixed(2)}%** → **${Number(c.fee_cut_percent).toFixed(2)}%**` + (fcRound ? ` (round **${fcRound}**)` : ""),
            onSent,
          });
        }
        prevReward = c.reward_cut_percent;
        prevFee = c.fee_cut_percent;
      }
      if (cutEvents.length === 0) {
        // First run, no change, or cut alerts disabled — safe to seed baseline now.
        snap.latest_cut_event_id = latestCut.event_id;
        snap.reward_cut_percent = latestCut.reward_cut_percent;
        snap.fee_cut_percent = latestCut.fee_cut_percent;
      } else {
        events.push(...cutEvents);
      }
    }

    // ── Reward not claimed for the CURRENT round (on-chain via Arbitrum RPC) ──
    // Source of truth: BondingManager.getTranscoder(orch).lastRewardRound.
    if (sub.notify_missed_reward) {
      const [onchainCurrentRound, onchainLastRewardRound] = await Promise.all([
        getCurrentRound().catch(() => null),
        getLastRewardRound(orchAddr).catch(() => null),
      ]);

      if (onchainCurrentRound != null && onchainLastRewardRound != null) {
        const currentRoundClaimed = onchainLastRewardRound >= onchainCurrentRound;

        // Also fetch round start time from API for the "active for ~Nh" message
        let roundStartedAt = null;
        try {
          const roundInfo = await lp(env, `/rounds/${onchainCurrentRound}`);
          roundStartedAt = roundInfo?.started_at ? new Date(roundInfo.started_at).getTime() : null;
        } catch {}

        console.log(`[missed-reward] sub=${sub.id} orch=${orchAddr.slice(0,10)} currentRound=${onchainCurrentRound} lastRewardRound=${onchainLastRewardRound} claimed=${currentRoundClaimed}`);

        if (!currentRoundClaimed) {
          const oneHourMs = 60 * 60 * 1000;
          const roundAgeMs = roundStartedAt ? Date.now() - roundStartedAt : null;

          // Only alert if round has been active for at least 1 hour (or we can't tell)
          if (roundAgeMs == null || roundAgeMs >= oneHourMs) {
            const lastAlertedAt = Number(prevSnap.last_missed_alert_at || 0);
            const cooldownMs = 35 * 60 * 1000; // > 30min cron interval to prevent same-round double-alert
            const lastAlertedRound = Number(prevSnap.last_missed_round || 0);
            const shouldAlert = lastAlertedRound !== onchainCurrentRound || (Date.now() - lastAlertedAt >= cooldownMs);
            if (shouldAlert) {
              const ageHours = roundAgeMs != null ? Math.floor(roundAgeMs / oneHourMs) : null;
              events.push({
                title: "🔴 Current Round Not Claimed",
                message: `Orchestrator \`${orchLabel}\` has not called reward() for the current round **${onchainCurrentRound}**` +
                  (ageHours != null ? ` (active for ~${ageHours}h)` : "") + `.`,
                onSent: () => {
                  snap.last_missed_alert_at = Date.now();
                  snap.last_missed_round = onchainCurrentRound;
                },
              });
            }
          }
        } else if (prevSnap.last_missed_round && prevSnap.last_missed_round < onchainCurrentRound) {
          // Orchestrator caught up — send resolution message and clear state
          events.push({
            title: "✅ Reward Claimed",
            message: `Orchestrator \`${orchLabel}\` claimed rewards for round **${onchainCurrentRound}**.`,
            onSent: () => {
              delete snap.last_missed_round;
              delete snap.last_missed_alert_at;
            },
          });
        }
      } else {
        console.warn(`[missed-reward] sub=${sub.id} on-chain RPC returned null, skipping`);
      }
    }

    // ── Detailed claim report — new reward events since last check ──
    if (sub.notify_claim_report) {
      try {
        const lastClaimEventId = prevSnap.last_claim_event_id;
        const params = {
          contract: "BondingManager",
          event_name: "Reward",
          address: orchAddr,
          with_valuations: true,
          sort: "block_desc",
          limit: 10,
        };
        const rewardEvents = await lp(env, `/events`, params);
        const allRewards = rewardEvents.data || [];

        // Filter to events newer than last notified
        const newRewards = [];
        for (const ev of allRewards) {
          if (ev.id === lastClaimEventId) break;
          newRewards.push(ev);
        }

        if (newRewards.length > 0) {
          const lines = [];
          for (const ev of newRewards.reverse()) {
            const totalLpt = Number(ev.amount_native || 0);
            const usdRow = (ev.valuations || []).find(v => v.asset === "LPT");
            const totalUsd = usdRow ? Number(usdRow.amount_usd || 0) : null;
            const lptPrice = usdRow && totalLpt > 0 ? totalUsd / totalLpt : null;

            // Calculate split using the orchestrator's cut at that time
            // (We use current reward_cut_percent — a more accurate impl would
            // look up the cut effective at ev.block_number from cuts-history)
            const rewardCutPct = Number(latestCut?.reward_cut_percent || 0);
            const rewardCutFrac = rewardCutPct / 100;

            const orchShareLpt = totalLpt * rewardCutFrac;
            const delegatorsShareLpt = totalLpt - orchShareLpt;
            const orchShareUsd = totalUsd != null ? totalUsd * rewardCutFrac : null;
            const delegatorsShareUsd = totalUsd != null ? totalUsd - orchShareUsd : null;

            // User's slice — proportional to their stake out of total stake
            const userStake = Number(activeDelegation.bonded_principal || 0);
            const totalStake = Number(orch.total_stake || 0);
            const myShareFrac = totalStake > 0 ? userStake / totalStake : 0;
            const myLpt = delegatorsShareLpt * myShareFrac;
            const myUsd = delegatorsShareUsd != null ? delegatorsShareUsd * myShareFrac : null;

            const date = new Date(ev.block_timestamp).toLocaleString();
            const roundNum = blockToRound(ev.block_number);
            lines.push(
              `🟢 *Round ${roundNum ?? "?"}* · ${date}\n` +
              `Total minted: \`${totalLpt.toFixed(4)} LPT\`${totalUsd != null ? ` (~$${totalUsd.toFixed(2)})` : ""}\n` +
              `Orchestrator (${rewardCutPct.toFixed(2)}%): \`${orchShareLpt.toFixed(4)} LPT\`${orchShareUsd != null ? ` (~$${orchShareUsd.toFixed(2)})` : ""}\n` +
              `Delegators (${(100 - rewardCutPct).toFixed(2)}%): \`${delegatorsShareLpt.toFixed(4)} LPT\`${delegatorsShareUsd != null ? ` (~$${delegatorsShareUsd.toFixed(2)})` : ""}\n` +
              `*Your share* (${(myShareFrac * 100).toFixed(2)}% of pool): \`${myLpt.toFixed(6)} LPT\`${myUsd != null ? ` (~$${myUsd.toFixed(4)})` : ""}` +
              (lptPrice != null ? `\n_LPT @ $${lptPrice.toFixed(4)}_` : "")
            );
          }

          const newestId = allRewards[0]?.id;
          events.push({
            title: `💰 Rewards Claimed (${newRewards.length} round${newRewards.length > 1 ? "s" : ""})`,
            message: `Orchestrator \`${orchLabel}\`\n\n${lines.join("\n\n")}`,
            onSent: () => { snap.last_claim_event_id = newestId; },
          });
        } else if (!lastClaimEventId && allRewards.length > 0) {
          // First time seeing this sub — just remember the most recent without spamming
          snap.last_claim_event_id = allRewards[0].id;
        }
      } catch (e) {
        console.warn(`Claim report fetch failed for sub ${sub.id}:`, e.message);
      }
    }

    // ── Governance: orchestrator hasn't voted on an active treasury proposal ──
    // Default-on: treated as enabled unless explicitly turned off.
    if (sub.notify_governance !== false && Array.isArray(gov.proposals) && gov.proposals.length) {
      snap.gov_notified = { ...(prevSnap.gov_notified || {}) };
      for (const p of gov.proposals) {
        let voted = null;
        try { voted = await hasVoted(BigInt(p.id), orchAddr); }
        catch (e) { console.warn(`hasVoted failed for ${p.id}:`, e.message); }
        if (voted === false && !snap.gov_notified[p.id]) {
          const left = (gov.currentRound != null && p.voteEnd != null) ? p.voteEnd - gov.currentRound : null;
          const pid = p.id;
          events.push({
            title: "🗳 Treasury proposal needs a vote",
            message: `A Livepeer treasury proposal (\`#${String(p.id).slice(0, 8)}…\`) is open and your orchestrator \`${orchLabel}\` has **not voted** yet.` +
              (p.voteEnd != null ? ` Voting ends at round **${p.voteEnd}**${left != null && left >= 0 ? ` (~${left} round${left === 1 ? "" : "s"} left)` : ""}.` : "") +
              `\n\nAs a delegator you can vote to override your orchestrator: https://explorer.livepeer.org/voting`,
            onSent: () => { snap.gov_notified[pid] = Date.now(); },
          });
        } else if (voted === true && snap.gov_notified[p.id]) {
          const pid = p.id;
          events.push({
            title: "✅ Orchestrator Voted",
            message: `Your orchestrator \`${orchLabel}\` has now voted on treasury proposal \`#${String(p.id).slice(0, 8)}…\`.`,
            onSent: () => { delete snap.gov_notified[pid]; },
          });
        }
      }
      // Drop tracking for proposals that are no longer active.
      const activeIds = new Set(gov.proposals.map(p => String(p.id)));
      for (const k of Object.keys(snap.gov_notified)) if (!activeIds.has(k)) delete snap.gov_notified[k];
    }

    return { events, snap };
  } catch (e) {
    console.error(`Check failed for sub ${sub.id}:`, e.message);
    return { events: [], snap: null };
  }
}

async function snapshotTreasury(env) {
  // Once-a-day snapshot of treasury LPT balance, stored as `treasury:YYYY-MM-DD`
  const dateKey = todayKey();
  const existing = await env.SUBS.get(`treasury:${dateKey}`);
  if (existing) return; // already snapshotted today
  const balance = await fetchTreasuryBalance();
  if (balance == null) {
    console.warn("Treasury balance fetch returned null");
    return;
  }
  await env.SUBS.put(`treasury:${dateKey}`, JSON.stringify({ date: dateKey, balance, fetched_at: Date.now() }));
  console.log(`Treasury snapshot: ${dateKey} = ${balance.toFixed(2)} LPT`);
}

async function getTreasuryHistory(env, days = 90) {
  // List all treasury:* keys, sort by date desc, return last N days
  const list = await env.SUBS.list({ prefix: "treasury:" });
  const snapshots = [];
  for (const k of list.keys) {
    const snap = await env.SUBS.get(k.name, "json");
    if (snap) snapshots.push(snap);
  }
  return snapshots
    .sort((a, b) => a.date.localeCompare(b.date))
    .slice(-days);
}

async function snapshotDailyStats(env) {
  // Store yesterday's completed payouts + rewards (USD valuations are ready for previous days)
  const yesterday = new Date(Date.now() - 86400_000).toISOString().slice(0, 10);
  const today = todayKey();
  const key = `daily:${yesterday}`;
  if (await env.SUBS.get(key)) return;
  const [payRes, rewRes] = await Promise.all([
    lp(env, "/aggregations/events", { contract: "TicketBroker", event_name: "WinningTicketRedeemed",
      bucket: "day", metric: "sum_amount_usd", from: yesterday, to: today }).catch(() => null),
    lp(env, "/aggregations/events", { contract: "BondingManager", event_name: "Reward",
      bucket: "day", metric: "sum_amount_usd", from: yesterday, to: today }).catch(() => null),
  ]);
  const payouts_usd = (payRes?.results || []).reduce((s, b) => s + Number(b.value || 0), 0);
  const rewards_usd = (rewRes?.results || []).reduce((s, b) => s + Number(b.value || 0), 0);
  await env.SUBS.put(key, JSON.stringify({ date: yesterday, payouts_usd, rewards_usd }), { expirationTtl: 95 * 86400 });
  console.log(`Daily stats: ${yesterday} payouts=$${payouts_usd.toFixed(2)} rewards=$${rewards_usd.toFixed(2)}`);
}

async function getDailyHistory(env, days = 90) {
  const list = await env.SUBS.list({ prefix: "daily:" });
  const records = [];
  for (const k of list.keys) {
    const val = await env.SUBS.get(k.name, "json");
    if (val) records.push(val);
  }
  return records
    .sort((a, b) => a.date.localeCompare(b.date))
    .slice(-days);
}

// Dispatch each event; advance gated snapshot state only on successful delivery,
// then persist the snapshot once. Returns nothing.
async function processSub(env, sub, gov) {
  const { events, snap } = await checkSubscription(env, sub, gov);
  for (const ev of events) {
    const ok = await dispatch(env, sub, ev.title, ev.message);
    if (ok && typeof ev.onSent === "function") ev.onSent();
    else if (!ok) console.warn(`Dispatch failed (will retry) sub=${sub.id}: ${ev.title}`);
  }
  if (snap) await env.SNAP.put(`snap:${sub.id}`, JSON.stringify(snap));
  return events;
}

async function runCron(env) {
  const subs = await listAllSubs(env);
  console.log(`Cron: ${subs.length} subscriptions to check`);

  // Fetch active governance proposals + current round once per tick (shared by all subs).
  const gov = { proposals: [], currentRound: null };
  try { gov.proposals = await getActiveProposals(env); }
  catch (e) { console.error("Governance fetch failed:", e.message); }
  try { gov.currentRound = await getCurrentRound(); } catch {}

  for (const sub of subs) await processSub(env, sub, gov);

  try { await snapshotTreasury(env); }
  catch (e) { console.error("Treasury snapshot failed:", e.message); }
  try { await snapshotDailyStats(env); }
  catch (e) { console.error("Daily stats snapshot failed:", e.message); }
  try { await runDigests(env, subs); }
  catch (e) { console.error("Digests failed:", e.message); }
}

// ─── Weekly / monthly earnings digests ───────────────────────────────────────
// ISO-week key, e.g. "2026-W22". Used to fire a weekly digest once per week.
function isoWeekKey(d = new Date()) {
  const date = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = date.getUTCDay() || 7;            // Mon=1..Sun=7
  date.setUTCDate(date.getUTCDate() + 4 - day); // nearest Thursday
  const yearStart = new Date(Date.UTC(date.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((date - yearStart) / 86400000 + 1) / 7);
  return `${date.getUTCFullYear()}-W${String(week).padStart(2, "0")}`;
}
function monthKey(d = new Date()) {
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

// Sum a delegator's earnings (LPT + USD) for an orchestrator over [from,to).
// Uses the same proportional-share math as the per-event claim report.
async function computeEarnings(env, sub, orchAddr, from, to) {
  const [rewAgg, payAgg, orch, del] = await Promise.all([
    lp(env, "/aggregations/events", { contract: "BondingManager", event_name: "Reward",
      address: orchAddr, bucket: "day", metric: "sum_amount_usd", from, to }).catch(() => null),
    lp(env, "/aggregations/events", { contract: "TicketBroker", event_name: "WinningTicketRedeemed",
      address: orchAddr, bucket: "day", metric: "sum_amount_usd", from, to }).catch(() => null),
    lp(env, `/orchestrators/${orchAddr}`).catch(() => null),
    lp(env, `/delegators/${sub.wallet.toLowerCase()}`).catch(() => null),
  ]);
  const orchRewardsUsd = (rewAgg?.results || []).reduce((s, b) => s + Number(b.value || 0), 0);
  const orchPayoutsUsd = (payAgg?.results || []).reduce((s, b) => s + Number(b.value || 0), 0);

  const rewardCutFrac = Number(orch?.reward_cut_percent || 0) / 100;
  const totalStake = Number(orch?.total_stake || 0);
  const myDeleg = (del?.delegations || []).find(d => (d.delegate_address || "").toLowerCase() === orchAddr.toLowerCase());
  const userStake = Number(myDeleg?.bonded_principal || 0);
  const myShareFrac = totalStake > 0 ? userStake / totalStake : 0;

  // Delegators get (1 - rewardCut) of inflation rewards; payouts (fees) follow the
  // fee cut, approximated here with the same pool-share factor.
  const myRewardsUsd = orchRewardsUsd * (1 - rewardCutFrac) * myShareFrac;
  const myPayoutsUsd = orchPayoutsUsd * myShareFrac;
  return {
    orchRewardsUsd, orchPayoutsUsd,
    myRewardsUsd, myPayoutsUsd,
    myTotalUsd: myRewardsUsd + myPayoutsUsd,
    sharePct: myShareFrac * 100,
  };
}

async function sendDigest(env, sub, period, from, to) {
  // Resolve the active orchestrator for this wallet.
  let orchAddr = null;
  try {
    const del = await lp(env, `/delegators/${sub.wallet.toLowerCase()}`);
    const active = (del.delegations || []).sort((a, b) => Number(b.as_of_block) - Number(a.as_of_block))[0];
    orchAddr = active?.delegate_address;
  } catch {}
  if (!orchAddr) return false;

  const e = await computeEarnings(env, sub, orchAddr, from, to);
  const orchLabel = escapeMd(orchAddr.slice(0, 10));
  const usd = (n) => `$${Number(n).toFixed(2)}`;
  const title = period === "weekly" ? "📊 Weekly Earnings Digest" : "📊 Monthly Earnings Digest";
  const message =
    `Your earnings from \`${orchLabel}\` (${from} → ${to}):\n\n` +
    `*Your reward share:* ${usd(e.myRewardsUsd)}\n` +
    `*Your payout share:* ${usd(e.myPayoutsUsd)}\n` +
    `*Total:* ${usd(e.myTotalUsd)}\n` +
    `_Pool share: ${e.sharePct.toFixed(2)}%_`;
  return dispatch(env, sub, title, message);
}

// Fire weekly/monthly digests at most once per period per sub, gated by a KV
// marker. Runs every cron tick but only sends when a new period boundary passed.
async function runDigests(env, subs) {
  const now = new Date();
  const curWeek = isoWeekKey(now);
  const curMonth = monthKey(now);
  // Window for "last week" = previous 7 days; "last month" = previous 30 days.
  const today = todayKey();
  const weekFrom = new Date(Date.now() - 7 * 86400_000).toISOString().slice(0, 10);
  const monthFrom = new Date(Date.now() - 30 * 86400_000).toISOString().slice(0, 10);

  for (const sub of subs) {
    if (sub.notify_weekly_digest) {
      const key = `digest:w:${sub.id}:${curWeek}`;
      if (!(await env.SUBS.get(key))) {
        const ok = await sendDigest(env, sub, "weekly", weekFrom, today);
        if (ok) await env.SUBS.put(key, "1", { expirationTtl: 40 * 86400 });
      }
    }
    if (sub.notify_monthly_digest) {
      const key = `digest:m:${sub.id}:${curMonth}`;
      if (!(await env.SUBS.get(key))) {
        const ok = await sendDigest(env, sub, "monthly", monthFrom, today);
        if (ok) await env.SUBS.put(key, "1", { expirationTtl: 70 * 86400 });
      }
    }
  }
}

// ─── HTTP routes ─────────────────────────────────────────────────────────────
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // Set CORS headers scoped to this request's origin
  CORS_HEADERS = corsHeaders(request.headers.get("Origin") || "");

  if (method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });

  // POST /subscriptions
  if (method === "POST" && path === "/subscriptions") {
    const body = await request.json().catch(() => ({}));
    const { client_id, tg_user_id, wallet, channel, notify_reward_cut, notify_fee_cut, notify_missed_reward, notify_claim_report, notify_governance, notify_weekly_digest, notify_monthly_digest, telegram_chat_id, email_address, discord_webhook_url, discord_user_id, discord_username } = body;

    if (!isUuid(client_id)) return err("Invalid client_id");
    if (!wallet || !/^0x[a-f0-9]{40}$/i.test(wallet)) return err("Invalid wallet address");
    if (!ALLOWED_CHANNELS.includes(channel)) return err(`Channel must be one of: ${ALLOWED_CHANNELS.join(", ")}`);
    if (channel === "telegram" && !telegram_chat_id) return err("telegram_chat_id required for Telegram channel");
    if (channel === "telegram" && !/^-?\d{5,15}$/.test(String(telegram_chat_id))) return err("Invalid telegram_chat_id");
    if (channel === "email" && !email_address) return err("email_address required for email channel");
    if (channel === "email" && !/^[^\s@]{1,64}@[^\s@]{1,255}$/.test(email_address)) return err("Invalid email_address");
    if (channel === "discord" && !discord_user_id && !discord_webhook_url) return err("discord_user_id or discord_webhook_url required for Discord channel");
    if (discord_webhook_url) {
      try {
        const whu = new URL(discord_webhook_url);
        if (whu.protocol !== "https:" || !whu.hostname.endsWith("discord.com") || !whu.pathname.startsWith("/api/webhooks/")) return err("Invalid discord_webhook_url");
      } catch { return err("Invalid discord_webhook_url"); }
    }
    if (!notify_reward_cut && !notify_fee_cut && !notify_missed_reward && !notify_claim_report && !notify_governance && !notify_weekly_digest && !notify_monthly_digest) return err("Select at least one notification type");

    const existing = await listSubsByClient(env, client_id);
    if (existing.length >= MAX_SUBS_PER_CLIENT) return err(`Subscription limit reached (${MAX_SUBS_PER_CLIENT}). Delete one first.`);

    const sub = {
      id: newId(),
      client_id,
      tg_user_id: tg_user_id || null,
      wallet: wallet.toLowerCase(),
      channel,
      telegram_chat_id: telegram_chat_id || null,
      email_address: email_address || null,
      discord_user_id: discord_user_id || null,
      discord_username: discord_username || null,
      discord_webhook_url: discord_webhook_url || null,
      notify_reward_cut: !!notify_reward_cut,
      notify_fee_cut: !!notify_fee_cut,
      notify_missed_reward: !!notify_missed_reward,
      notify_claim_report: !!notify_claim_report,
      // Governance defaults ON unless explicitly disabled; digests are opt-in.
      notify_governance: notify_governance !== false,
      notify_weekly_digest: !!notify_weekly_digest,
      notify_monthly_digest: !!notify_monthly_digest,
      created_at: Date.now(),
    };
    await saveSub(env, sub);

    const types = [];
    if (sub.notify_reward_cut) types.push("• Reward cut changes");
    if (sub.notify_fee_cut) types.push("• Fee cut changes");
    if (sub.notify_missed_reward) types.push("• Missed rewards");
    if (sub.notify_claim_report) types.push("• Detailed claim reports");
    if (sub.notify_governance) types.push("• Treasury proposal votes");
    if (sub.notify_weekly_digest) types.push("• Weekly earnings digest");
    if (sub.notify_monthly_digest) types.push("• Monthly earnings digest");
    await dispatch(env, sub,
      "✅ Subscription active",
      `Now monitoring \`${wallet}\`\n\n${types.join("\n")}\n\nChecks run every 30 minutes.`
    );

    return json({ subscription: sub });
  }

  // GET /subscriptions?client_id=... OR ?tg_user_id=...
  if (method === "GET" && path === "/subscriptions") {
    const clientId = url.searchParams.get("client_id");
    const tgUserId = url.searchParams.get("tg_user_id");
    let subs = [];
    if (isUuid(clientId)) {
      subs = await listSubsByClient(env, clientId);
    }
    if (tgUserId) {
      // Also include subs belonging to this Telegram user (across devices)
      const all = await listAllSubs(env);
      const tgSubs = all.filter(s => String(s.tg_user_id || "") === String(tgUserId));
      // Merge unique by id
      const ids = new Set(subs.map(s => s.id));
      for (const s of tgSubs) if (!ids.has(s.id)) subs.push(s);
    }
    if (!isUuid(clientId) && !tgUserId) return err("Need client_id or tg_user_id");
    return json({ subscriptions: subs });
  }

  // DELETE /subscriptions/:id
  if (method === "DELETE" && path.startsWith("/subscriptions/")) {
    const id = path.split("/").pop();
    const callerClientId = request.headers.get("X-Client-Id");
    const callerTgUserId = request.headers.get("X-Tg-User-Id");
    if (!isUuid(callerClientId) && !callerTgUserId) return err("Invalid auth header", 401);
    const sub = await env.SUBS.get(`sub:${id}`, "json");
    if (!sub) return err("Subscription not found", 404);
    const ownedByClient = callerClientId && sub.client_id === callerClientId;
    const ownedByTgUser = callerTgUserId && String(sub.tg_user_id || "") === String(callerTgUserId);
    if (!ownedByClient && !ownedByTgUser) return err("Forbidden", 403);
    await deleteSub(env, sub);
    return json({ ok: true });
  }

  // POST /telegram/link
  if (method === "POST" && path === "/telegram/link") {
    const code = newCode();
    await env.CODES.put(`code:${code}`, JSON.stringify({ created_at: Date.now() }), { expirationTtl: 600 });
    return json({ code, bot_username: env.TELEGRAM_BOT_USERNAME || "your_bot", expires_in: 600 });
  }

  // GET /telegram/poll/:code
  if (method === "GET" && path.startsWith("/telegram/poll/")) {
    const code = path.split("/").pop();
    const codeData = await env.CODES.get(`code:${code}`, "json");
    if (!codeData) return err("Code expired or invalid", 404);
    if (codeData.chat_id) {
      await env.CODES.delete(`code:${code}`);
      return json({ linked: true, telegram_chat_id: codeData.chat_id, telegram_username: codeData.username });
    }
    return json({ linked: false });
  }

  // ── Discord OAuth ────────────────────────────────────────────────────────────

  // POST /discord/link — generate OAuth state, return authorization URL
  if (method === "POST" && path === "/discord/link") {
    if (!env.DISCORD_CLIENT_ID) return err("Discord not configured (missing DISCORD_CLIENT_ID)");
    const state = crypto.randomUUID(); // full 128-bit UUID
    await env.CODES.put(`discord_state:${state}`, "", { expirationTtl: 600 });
    // Derive the callback from THIS worker's origin so it always matches the
    // deployed host (hardcoding broke Discord linking when the host changed).
    const redirectUri = `${url.origin}/discord/callback`;
    const params = new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "identify applications.commands",
      integration_type: "1",  // 1 = user install (allows DMs without shared server)
      state,
    });
    return json({ auth_url: `https://discord.com/api/oauth2/authorize?${params}`, state, expires_in: 600 });
  }

  // GET /discord/callback — OAuth code exchange (redirect from Discord)
  if (method === "GET" && path === "/discord/callback") {
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const redirectFrontend = "https://livewatcher.xyz";
    if (!code || !state) return Response.redirect(`${redirectFrontend}?discord_error=missing_params`, 302);
    const stateKey = `discord_state:${state}`;
    const existing = await env.CODES.get(stateKey);
    if (existing === null) return Response.redirect(`${redirectFrontend}?discord_error=expired`, 302);
    // Exchange code for access token
    const tokenRes = await fetch("https://discord.com/api/v10/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        client_secret: env.DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: `${url.origin}/discord/callback`,
      }),
    });
    if (!tokenRes.ok) return Response.redirect(`${redirectFrontend}?discord_error=token_exchange`, 302);
    const { access_token } = await tokenRes.json();
    // Fetch user info
    const userRes = await fetch("https://discord.com/api/v10/users/@me", {
      headers: { "Authorization": `Bearer ${access_token}` },
    });
    if (!userRes.ok) return Response.redirect(`${redirectFrontend}?discord_error=user_fetch`, 302);
    const user = await userRes.json();
    // Store user info keyed by state
    await env.CODES.put(stateKey, JSON.stringify({
      discord_user_id: user.id,
      discord_username: user.global_name || user.username,
    }), { expirationTtl: 600 });
    return Response.redirect(`${redirectFrontend}?discord_linked=1`, 302);
  }

  // GET /discord/poll/:state — frontend polls for completed OAuth
  if (method === "GET" && path.startsWith("/discord/poll/")) {
    const state = path.slice("/discord/poll/".length);
    const val = await env.CODES.get(`discord_state:${state}`);
    if (!val) return json({ linked: false });
    try {
      const data = JSON.parse(val);
      if (!data.discord_user_id) return json({ linked: false });
      await env.CODES.delete(`discord_state:${state}`); // consume — prevent replay
      return json({ linked: true, ...data });
    } catch { return json({ linked: false }); }
  }

  // POST /telegram/webhook (Telegram → us)
  if (method === "POST" && path === "/telegram/webhook") {
    const update = await request.json().catch(() => ({}));

    // Handle inline-keyboard button callbacks
    if (update.callback_query) {
      const cb = update.callback_query;
      const chatId = cb.message?.chat?.id;
      const messageId = cb.message?.message_id;
      const tgUserId = cb.from?.id;
      const dataStr = cb.data || "";

      if (dataStr === "close") {
        await editTelegram(env, chatId, messageId, "_Settings closed._", { inline_keyboard: [] });
        await answerCallback(env, cb.id);
        return json({ ok: true });
      }

      const m = dataStr.match(/^toggle:([^:]+):(\w+)$/);
      if (m) {
        const subId = m[1];
        const flag = m[2];
        const sub = await env.SUBS.get(`sub:${subId}`, "json");
        if (!sub) {
          await answerCallback(env, cb.id, "Subscription not found");
        } else if (String(sub.tg_user_id || "") !== String(tgUserId) && String(sub.telegram_chat_id) !== String(chatId)) {
          await answerCallback(env, cb.id, "Not your subscription");
        } else if (!NOTIFY_FLAGS.includes(flag)) {
          await answerCallback(env, cb.id, "Unknown setting");
        } else {
          // Effective state: governance is on unless explicitly false.
          const eff = (k) => k === "notify_governance" ? (sub.notify_governance !== false) : !!sub[k];
          // Prevent disabling the last enabled flag
          const enabled = NOTIFY_FLAGS.filter(eff).length;
          if (eff(flag) && enabled <= 1) {
            await answerCallback(env, cb.id, "At least one alert must remain enabled");
          } else {
            sub[flag] = !eff(flag);
            await saveSub(env, sub);
            const nickname = await resolveNickname(env, sub);
            const header = nickname ? `*Settings: ${escapeMd(nickname)}*\n\`${sub.wallet}\`` : `*Settings*\n\`${sub.wallet}\``;
            await editTelegram(env, chatId, messageId, header, settingsKeyboard(sub));
            await answerCallback(env, cb.id, `${flag.replace("notify_", "")}: ${sub[flag] ? "ON" : "OFF"}`);
          }
        }
        return json({ ok: true });
      }
    }

    const msg = update.message;
    if (msg?.text) {
      const text = msg.text.trim();
      const chatId = msg.chat.id;
      const username = msg.from?.username;
      const tgUserId = msg.from?.id;
      const cmd = text.split(/\s+/)[0].toLowerCase();
      const args = text.split(/\s+/).slice(1);

      // 6-digit linking code (still supported for the website's link flow)
      if (/^\d{6}$/.test(text)) {
        const codeData = await env.CODES.get(`code:${text}`, "json");
        if (codeData) {
          await env.CODES.put(`code:${text}`, JSON.stringify({ ...codeData, chat_id: chatId, username }), { expirationTtl: 600 });
          await sendTelegram(env, chatId, "✅ *Code accepted!* Return to LiveWatch to finish setup.");
        } else {
          await sendTelegram(env, chatId, "❌ Code not recognised or expired. Generate a new one in LiveWatch.");
        }
        return json({ ok: true });
      }

      if (cmd === "/start") {
        await sendTelegram(env, chatId,
          "*Welcome to LiveWatch!* 👋\n\n" +
          "I monitor Livepeer delegations and ping you when something changes.\n\n" +
          "*Quick setup:*\n" +
          "Use \`/add 0x…\` to subscribe to a wallet, or open the website and link your Telegram.\n\n" +
          BOT_HELP_TEXT
        );
        return json({ ok: true });
      }

      if (cmd === "/help") {
        await sendTelegram(env, chatId, BOT_HELP_TEXT);
        return json({ ok: true });
      }

      if (cmd === "/list") {
        const subs = await findUserSubs(env, tgUserId, chatId);
        if (subs.length === 0) {
          await sendTelegram(env, chatId, "_You have no active subscriptions._\n\nUse \`/add 0x…\` to subscribe to a wallet.");
        } else {
          const lines = [];
          for (let i = 0; i < subs.length; i++) {
            const nick = await resolveNickname(env, subs[i]);
            lines.push(formatSubLine(subs[i], i, nick));
          }
          await sendTelegram(env, chatId,
            `*Your subscriptions (${subs.length})*\n\n${lines.join("\n\n")}\n\n` +
            `_Legend: RC=reward cut · FC=fee cut · MR=missed reward · CR=claim reports · GV=treasury votes · WD=weekly digest · MD=monthly digest_`
          );
        }
        return json({ ok: true });
      }

      if (cmd === "/add") {
        const wallet = (args[0] || "").toLowerCase();
        if (!/^0x[a-f0-9]{40}$/i.test(wallet)) {
          await sendTelegram(env, chatId, "Usage: \`/add 0x…\` (wallet must be a valid 0x address)");
          return json({ ok: true });
        }
        // Check if already subscribed
        const existing = await findUserSubs(env, tgUserId, chatId);
        if (existing.some(s => s.wallet === wallet)) {
          await sendTelegram(env, chatId, `Already subscribed to \`${wallet}\`. See \`/list\` for your subs.`);
          return json({ ok: true });
        }
        if (existing.length >= MAX_SUBS_PER_CLIENT) {
          await sendTelegram(env, chatId, `Subscription limit reached (${MAX_SUBS_PER_CLIENT}). Use \`/remove N\` first.`);
          return json({ ok: true });
        }
        // Reuse a client_id if any of their subs has one (so management stays grouped)
        const clientId = existing[0]?.client_id || newId();
        const sub = {
          id: newId(),
          client_id: clientId,
          tg_user_id: tgUserId,
          wallet,
          channel: "telegram",
          telegram_chat_id: chatId,
          notify_reward_cut: true,
          notify_fee_cut: true,
          notify_missed_reward: true,
          notify_claim_report: false,
          notify_governance: true,
          notify_weekly_digest: false,
          notify_monthly_digest: false,
          created_at: Date.now(),
        };
        await saveSub(env, sub);
        await sendTelegram(env, chatId,
          `✅ *Subscription added!*\n\nMonitoring \`${wallet}\`\n\n` +
          `Defaults: reward cut, fee cut, missed reward, treasury-vote alerts ON · claim reports & digests OFF\n\n` +
          `Use \`/settings ${existing.length + 1}\` to change.`
        );
        return json({ ok: true });
      }

      if (cmd === "/remove") {
        const n = parseInt(args[0]);
        if (isNaN(n) || n < 1) {
          await sendTelegram(env, chatId, "Usage: \`/remove N\` (where N is the number from /list)");
          return json({ ok: true });
        }
        const subs = await findUserSubs(env, tgUserId, chatId);
        const sub = subs[n - 1];
        if (!sub) {
          await sendTelegram(env, chatId, `Subscription #${n} not found. Use /list to see your subs.`);
          return json({ ok: true });
        }
        await deleteSub(env, sub);
        await sendTelegram(env, chatId, `✅ Removed subscription for \`${sub.wallet}\``);
        return json({ ok: true });
      }

      if (cmd === "/nickname") {
        const n = parseInt(args[0]);
        const newNick = args.slice(1).join(" ").trim();
        if (isNaN(n) || n < 1 || !args[1]) {
          await sendTelegram(env, chatId, "Usage: \`/nickname N some name\` (or \`/nickname N clear\` to remove)");
          return json({ ok: true });
        }
        const subs = await findUserSubs(env, tgUserId, chatId);
        const sub = subs[n - 1];
        if (!sub) {
          await sendTelegram(env, chatId, `Subscription #${n} not found.`);
          return json({ ok: true });
        }
        const scope = sub.tg_user_id ? `tg:${sub.tg_user_id}` : `client:${sub.client_id}`;
        const key = `nick:${scope}:${sub.wallet}`;
        if (newNick.toLowerCase() === "clear") {
          await env.SUBS.delete(key);
          await sendTelegram(env, chatId, `Nickname cleared for \`${sub.wallet}\`.`);
        } else {
          await env.SUBS.put(key, newNick.slice(0, 80));
          await sendTelegram(env, chatId, `Nickname for \`${sub.wallet}\` set to *${escapeMd(newNick)}*.`);
        }
        return json({ ok: true });
      }

      if (cmd === "/settings") {
        const n = parseInt(args[0]);
        if (isNaN(n) || n < 1) {
          await sendTelegram(env, chatId, "Usage: \`/settings N\` (where N is the number from /list)");
          return json({ ok: true });
        }
        const subs = await findUserSubs(env, tgUserId, chatId);
        const sub = subs[n - 1];
        if (!sub) {
          await sendTelegram(env, chatId, `Subscription #${n} not found.`);
          return json({ ok: true });
        }
        const nickname = await resolveNickname(env, sub);
        const header = nickname ? `*Settings: ${escapeMd(nickname)}*\n\`${sub.wallet}\`` : `*Settings*\n\`${sub.wallet}\``;
        await sendTelegram(env, chatId, header, { reply_markup: settingsKeyboard(sub) });
        return json({ ok: true });
      }

      // Unknown command
      await sendTelegram(env, chatId, "Unknown command. Use /help to see what I can do.");
    }
    return json({ ok: true });
  }

  // POST /tg-login - verify and store Telegram login auth
  if (method === "POST" && path === "/tg-login") {
    const body = await request.json().catch(() => ({}));
    const { client_id, tg_auth } = body;
    if (!isUuid(client_id)) return err("Invalid client_id");
    if (!tg_auth || !tg_auth.id) return err("Missing tg_auth payload");
    const valid = await verifyTelegramAuth(env, tg_auth);
    if (!valid) return err("Telegram auth verification failed", 401);
    // Store user record (keyed by tg_user_id) and a client_id → tg_user link
    await env.SUBS.put(`tg_user:${tg_auth.id}`, JSON.stringify({
      tg_user_id: tg_auth.id,
      username: tg_auth.username || null,
      first_name: tg_auth.first_name || null,
      photo_url: tg_auth.photo_url || null,
      linked_at: Date.now(),
    }));
    await env.SUBS.put(`client_tg:${client_id}`, String(tg_auth.id));
    return json({ ok: true, tg_user_id: tg_auth.id });
  }

  // POST /nicknames - set/update wallet nickname (scoped to client_id or tg_user_id)
  if (method === "POST" && path === "/nicknames") {
    const body = await request.json().catch(() => ({}));
    const { client_id, tg_user_id, wallet, nickname } = body;
    if (!wallet || !/^0x[a-f0-9]{40}$/i.test(wallet)) return err("Invalid wallet");
    let scope;
    if (tg_user_id) scope = `tg:${tg_user_id}`;
    else if (isUuid(client_id)) scope = `client:${client_id}`;
    else return err("Need client_id or tg_user_id");
    const key = `nick:${scope}:${wallet.toLowerCase()}`;
    if (nickname && nickname.trim()) {
      await env.SUBS.put(key, nickname.trim().slice(0, 80));
    } else {
      await env.SUBS.delete(key);
    }
    return json({ ok: true });
  }

  // GET /treasury/history?days=90
  if (method === "GET" && path === "/treasury/history") {
    const days = Math.min(Math.max(parseInt(url.searchParams.get("days") || "90"), 1), 365);
    const history = await getTreasuryHistory(env, days);
    // Ensure today's snapshot exists (fire-and-forget if missing — won't block response)
    if (history.length === 0 || history[history.length - 1].date !== todayKey()) {
      // Try to add today's snapshot synchronously so the caller gets the latest value too
      try { await snapshotTreasury(env); }
      catch (e) { console.warn("Inline treasury snapshot failed:", e.message); }
      const refreshed = await getTreasuryHistory(env, days);
      return json({ history: refreshed });
    }
    return json({ history });
  }

  // GET /daily/history?days=90 — historical daily payouts + rewards from KV
  if (method === "GET" && path === "/daily/history") {
    const days = Math.min(Math.max(parseInt(url.searchParams.get("days") || "90"), 1), 365);
    const yesterday = new Date(Date.now() - 86400_000).toISOString().slice(0, 10);
    let history = await getDailyHistory(env, days);
    if (history.length === 0 || history[history.length - 1].date !== yesterday) {
      try { await snapshotDailyStats(env); } catch (e) { console.warn("Inline daily snapshot failed:", e.message); }
      history = await getDailyHistory(env, days);
    }
    return json({ history });
  }

  // POST /daily/backfill?days=90 — one-time bulk seed from Livepeer API (safe to re-run)
  if (method === "POST" && path === "/daily/backfill") {
    const days = Math.min(parseInt(url.searchParams.get("days") || "90"), 365);
    const toDate = todayKey();
    const fromDate = new Date(Date.now() - days * 86400_000).toISOString().slice(0, 10);
    const [payRes, rewRes] = await Promise.all([
      lp(env, "/aggregations/events", { contract: "TicketBroker", event_name: "WinningTicketRedeemed",
        bucket: "day", metric: "sum_amount_usd", from: fromDate, to: toDate }).catch(() => null),
      lp(env, "/aggregations/events", { contract: "BondingManager", event_name: "Reward",
        bucket: "day", metric: "sum_amount_usd", from: fromDate, to: toDate }).catch(() => null),
    ]);
    const payByDate = Object.fromEntries((payRes?.results || []).map(b => [b.bucket_start, Number(b.value || 0)]));
    const rewByDate = Object.fromEntries((rewRes?.results || []).map(b => [b.bucket_start, Number(b.value || 0)]));
    const allDates = new Set([...Object.keys(payByDate), ...Object.keys(rewByDate)]);
    let count = 0, skipped = 0;
    for (const date of allDates) {
      if (date >= toDate) continue; // skip today — bucket not complete
      const key = `daily:${date}`;
      if (await env.SUBS.get(key)) { skipped++; continue; } // idempotent — skip existing
      await env.SUBS.put(key, JSON.stringify({
        date,
        payouts_usd: payByDate[date] || 0,
        rewards_usd: rewByDate[date] || 0,
      }), { expirationTtl: 95 * 86400 });
      count++;
    }
    return json({ ok: true, populated: count, skipped, from: fromDate, to: toDate });
  }

  // POST /debug/trigger?sub_id=... — manually run check for one sub (or all) without waiting for cron
  // Also accepts ?wallet=... to look up by wallet address
  if (method === "POST" && path === "/debug/trigger") {
    const subId = url.searchParams.get("sub_id");
    const wallet = url.searchParams.get("wallet");
    let subs = [];
    if (subId) {
      const sub = await env.SUBS.get(`sub:${subId}`, "json");
      if (!sub) return err("Subscription not found", 404);
      subs = [sub];
    } else if (wallet) {
      const all = await listAllSubs(env);
      subs = all.filter(s => s.wallet === wallet.toLowerCase());
      if (subs.length === 0) return err("No subscriptions for that wallet", 404);
    } else {
      return err("Provide sub_id or wallet param");
    }
    const gov = { proposals: [], currentRound: null };
    try { gov.proposals = await getActiveProposals(env); } catch (e) { console.warn("gov fetch failed:", e.message); }
    try { gov.currentRound = await getCurrentRound(); } catch {}
    const results = [];
    for (const sub of subs) {
      const { events, snap } = await checkSubscription(env, sub, gov);
      const dispatched = [];
      for (const ev of events) {
        const ok = await dispatch(env, sub, ev.title, ev.message);
        if (ok && typeof ev.onSent === "function") ev.onSent();
        dispatched.push({ title: ev.title, sent: ok });
      }
      if (snap) await env.SNAP.put(`snap:${sub.id}`, JSON.stringify(snap));
      results.push({ sub_id: sub.id, wallet: sub.wallet, events_found: events.length, dispatched });
    }
    return json({ ok: true, results });
  }

  // GET /debug/snap?sub_id=... — inspect stored snapshot for a subscription
  if (method === "GET" && path === "/debug/snap") {
    const subId = url.searchParams.get("sub_id");
    const wallet = url.searchParams.get("wallet");
    if (subId) {
      const snap = await env.SNAP.get(`snap:${subId}`, "json");
      const sub = await env.SUBS.get(`sub:${subId}`, "json");
      return json({ sub, snap });
    } else if (wallet) {
      const all = await listAllSubs(env);
      const subs = all.filter(s => s.wallet === wallet.toLowerCase());
      const out = [];
      for (const sub of subs) {
        const snap = await env.SNAP.get(`snap:${sub.id}`, "json");
        out.push({ sub, snap });
      }
      return json({ results: out });
    }
    return err("Provide sub_id or wallet param");
  }

  if (path === "/" || path === "/health") return json({ status: "ok", service: "livewatch-backend" });
  return err("Not found", 404);
}

export default {
  async fetch(request, env, ctx) {
    try { return await handleRequest(request, env); }
    catch (e) { console.error("Unhandled:", e); return err(`Internal error: ${e.message}`, 500); }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runCron(env));
  },
};
