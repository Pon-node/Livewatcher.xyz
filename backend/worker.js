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

// Livepeer Treasury contract (LivepeerGovernor on Arbitrum)
const TREASURY_ADDR = "0xf82C1FF415F1fCf582554fDba790E27019c8E8C4";
const LPT_TOKEN_ADDR = "0x289ba1701C2F088cf0faf8B3705246331cB8A839";
// BondingManager proxy on Arbitrum One
const BONDING_MANAGER_ADDR = "0x35Bcf3c30594191d53231e4ff333e8a770453e40";
// RoundsManager proxy on Arbitrum One
const ROUNDS_MANAGER_ADDR = "0xdd6f56DcC28D3F5f27084381fE8Df634985cc39f";
const ARB_RPCS = [
  "https://arbitrum-one-rpc.publicnode.com",
  "https://arbitrum.drpc.org",
  "https://arb1.arbitrum.io/rpc",
];

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Client-Id, X-Tg-User-Id",
  "Access-Control-Max-Age": "86400",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}
function err(message, status = 400) { return json({ error: message }, status); }
function newId() { return crypto.randomUUID(); }
function newCode() { return String(Math.floor(100000 + Math.random() * 900000)); }
function todayKey() { return new Date().toISOString().slice(0, 10); }

function isUuid(s) {
  return typeof s === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
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
  if (!res.ok) console.warn(`Discord send failed: ${res.status} ${await res.text()}`);
  return res.ok;
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
  const label = nickname ? `*${nickname}* (\`${sub.wallet.slice(0, 8)}…${sub.wallet.slice(-4)}\`)` : `\`${sub.wallet.slice(0, 8)}…${sub.wallet.slice(-4)}\``;
  const flags = [];
  if (sub.notify_reward_cut) flags.push("RC");
  if (sub.notify_fee_cut) flags.push("FC");
  if (sub.notify_missed_reward) flags.push("MR");
  if (sub.notify_claim_report) flags.push("CR");
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
  const walletLabel = nickname ? `*${nickname}* (\`${sub.wallet}\`)` : `\`${sub.wallet}\``;
  const text = `*${title}*\n\n${message}\n\n_Wallet: ${walletLabel}_`;
  if (sub.channel === "telegram" && sub.telegram_chat_id) {
    return sendTelegram(env, sub.telegram_chat_id, text);
  }
  if (sub.channel === "email" && sub.email_address) {
    return sendEmail(env, sub.email_address, title, text);
  }
  if (sub.channel === "discord" && sub.discord_webhook_url) {
    return sendDiscord(env, sub.discord_webhook_url, title, text);
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
async function checkSubscription(env, sub) {
  const events = [];
  const wallet = sub.wallet.toLowerCase();

  try {
    const del = await lp(env, `/delegators/${wallet}`);
    if (!del.delegations || del.delegations.length === 0) return events;
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

    // cuts-history is sorted ascending (oldest first); newest cut is the last element
    const cuts = cutsRes.data || [];
    const latestCut = cuts.length > 0 ? cuts[cuts.length - 1] : null;
    const stakes = stakeRes.data || [];
    const prevSnap = (await env.SNAP.get(`snap:${sub.id}`, "json")) || {};

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

    // Reward cut change — compare latest (last) cut event against snapshot
    if (sub.notify_reward_cut && prevSnap.latest_cut_event_id && latestCut) {
      if (latestCut.event_id !== prevSnap.latest_cut_event_id &&
          latestCut.reward_cut_percent !== prevSnap.reward_cut_percent) {
        const up = Number(latestCut.reward_cut_percent) > Number(prevSnap.reward_cut_percent);
        const rcRound = blockToRound(latestCut.block_number);
        events.push({
          title: `${up ? "⚠️" : "✅"} Reward Cut ${up ? "Increased" : "Decreased"}`,
          message: `Orchestrator \`${orch.display_name || orchAddr.slice(0, 10)}\` changed reward cut from **${Number(prevSnap.reward_cut_percent).toFixed(2)}%** → **${Number(latestCut.reward_cut_percent).toFixed(2)}%**` + (rcRound ? ` (round **${rcRound}**)` : ""),
        });
      }
    }

    // Fee cut change — compare latest (last) cut event against snapshot
    if (sub.notify_fee_cut && prevSnap.latest_cut_event_id && latestCut) {
      if (latestCut.event_id !== prevSnap.latest_cut_event_id &&
          latestCut.fee_cut_percent !== prevSnap.fee_cut_percent) {
        const up = Number(latestCut.fee_cut_percent) > Number(prevSnap.fee_cut_percent);
        const fcRound = blockToRound(latestCut.block_number);
        events.push({
          title: `${up ? "⚠️" : "✅"} Fee Cut ${up ? "Increased" : "Decreased"}`,
          message: `Orchestrator \`${orch.display_name || orchAddr.slice(0, 10)}\` changed fee cut from **${Number(prevSnap.fee_cut_percent).toFixed(2)}%** → **${Number(latestCut.fee_cut_percent).toFixed(2)}%**` + (fcRound ? ` (round **${fcRound}**)` : ""),
        });
      }
    }

    // Reward not claimed for the CURRENT round (on-chain check via Arbitrum RPC).
    // Source of truth: BondingManager.getTranscoder(orch).lastRewardRound on-chain.
    // If lastRewardRound >= currentRound, they've called reward() for this round.
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
                message: `Orchestrator \`${orch.display_name || orchAddr.slice(0, 10)}\` has not called reward() for the current round **${onchainCurrentRound}**` +
                  (ageHours != null ? ` (active for ~${ageHours}h)` : "") + `.`,
              });
              prevSnap.last_missed_alert_at = Date.now();
              prevSnap.last_missed_round = onchainCurrentRound;
            }
          }
        } else if (prevSnap.last_missed_round && prevSnap.last_missed_round < onchainCurrentRound) {
          // Orchestrator caught up — send resolution message and clear state
          events.push({
            title: "✅ Reward Claimed",
            message: `Orchestrator \`${orch.display_name || orchAddr.slice(0, 10)}\` claimed rewards for round **${onchainCurrentRound}**.`,
          });
          delete prevSnap.last_missed_round;
          delete prevSnap.last_missed_alert_at;
        }
      } else {
        console.warn(`[missed-reward] sub=${sub.id} on-chain RPC returned null, skipping`);
      }
    }

    // Detailed claim report — new reward events since last check
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

          events.push({
            title: `💰 Rewards Claimed (${newRewards.length} round${newRewards.length > 1 ? "s" : ""})`,
            message: `Orchestrator \`${orch.display_name || orchAddr.slice(0, 10)}\`\n\n${lines.join("\n\n")}`,
          });

          prevSnap.last_claim_event_id = allRewards[0]?.id;
        } else if (!lastClaimEventId && allRewards.length > 0) {
          // First time seeing this sub — just remember the most recent without spamming
          prevSnap.last_claim_event_id = allRewards[0].id;
        }
      } catch (e) {
        console.warn(`Claim report fetch failed for sub ${sub.id}:`, e.message);
      }
    }

    // Update snapshot — store the latest (last) cut event since cuts-history is ascending
    await env.SNAP.put(`snap:${sub.id}`, JSON.stringify({
      ...prevSnap,
      orchestrator_address: orchAddr,
      reward_cut_percent: latestCut?.reward_cut_percent,
      fee_cut_percent: latestCut?.fee_cut_percent,
      latest_cut_event_id: latestCut?.event_id,
      latest_round_seen: stakes[stakes.length - 1]?.round,
      checked_at: Date.now(),
    }));
  } catch (e) {
    console.error(`Check failed for sub ${sub.id}:`, e.message);
  }
  return events;
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

async function runCron(env) {
  const subs = await listAllSubs(env);
  console.log(`Cron: ${subs.length} subscriptions to check`);
  for (const sub of subs) {
    const events = await checkSubscription(env, sub);
    for (const ev of events) await dispatch(env, sub, ev.title, ev.message);
  }
  // Once-a-day treasury snapshot (idempotent; only writes if today's snapshot doesn't exist)
  try { await snapshotTreasury(env); }
  catch (e) { console.error("Treasury snapshot failed:", e.message); }
}

// ─── HTTP routes ─────────────────────────────────────────────────────────────
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });

  // POST /subscriptions
  if (method === "POST" && path === "/subscriptions") {
    const body = await request.json().catch(() => ({}));
    const { client_id, tg_user_id, wallet, channel, notify_reward_cut, notify_fee_cut, notify_missed_reward, notify_claim_report, telegram_chat_id, email_address, discord_webhook_url } = body;

    if (!isUuid(client_id)) return err("Invalid client_id");
    if (!wallet || !/^0x[a-f0-9]{40}$/i.test(wallet)) return err("Invalid wallet address");
    if (!ALLOWED_CHANNELS.includes(channel)) return err(`Channel must be one of: ${ALLOWED_CHANNELS.join(", ")}`);
    if (channel === "telegram" && !telegram_chat_id) return err("telegram_chat_id required for Telegram channel");
    if (channel === "email" && !email_address) return err("email_address required for email channel");
    if (channel === "discord" && !discord_webhook_url) return err("discord_webhook_url required for Discord channel");
    if (!notify_reward_cut && !notify_fee_cut && !notify_missed_reward && !notify_claim_report) return err("Select at least one notification type");

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
      discord_webhook_url: discord_webhook_url || null,
      notify_reward_cut: !!notify_reward_cut,
      notify_fee_cut: !!notify_fee_cut,
      notify_missed_reward: !!notify_missed_reward,
      notify_claim_report: !!notify_claim_report,
      created_at: Date.now(),
    };
    await saveSub(env, sub);

    const types = [];
    if (sub.notify_reward_cut) types.push("• Reward cut changes");
    if (sub.notify_fee_cut) types.push("• Fee cut changes");
    if (sub.notify_missed_reward) types.push("• Missed rewards");
    if (sub.notify_claim_report) types.push("• Detailed claim reports");
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
        } else if (!["notify_reward_cut", "notify_fee_cut", "notify_missed_reward", "notify_claim_report"].includes(flag)) {
          await answerCallback(env, cb.id, "Unknown setting");
        } else {
          // Prevent disabling the last enabled flag
          const enabled = ["notify_reward_cut", "notify_fee_cut", "notify_missed_reward", "notify_claim_report"]
            .filter(k => sub[k]).length;
          if (sub[flag] && enabled <= 1) {
            await answerCallback(env, cb.id, "At least one alert must remain enabled");
          } else {
            sub[flag] = !sub[flag];
            await saveSub(env, sub);
            const nickname = await resolveNickname(env, sub);
            const header = nickname ? `*Settings: ${nickname}*\n\`${sub.wallet}\`` : `*Settings*\n\`${sub.wallet}\``;
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
            `_Legend: RC=reward cut · FC=fee cut · MR=missed reward · CR=claim reports_`
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
          created_at: Date.now(),
        };
        await saveSub(env, sub);
        await sendTelegram(env, chatId,
          `✅ *Subscription added!*\n\nMonitoring \`${wallet}\`\n\n` +
          `Defaults: reward cut, fee cut, missed reward alerts ON · claim reports OFF\n\n` +
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
          await sendTelegram(env, chatId, `Nickname for \`${sub.wallet}\` set to *${newNick}*.`);
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
        const header = nickname ? `*Settings: ${nickname}*\n\`${sub.wallet}\`` : `*Settings*\n\`${sub.wallet}\``;
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
    const results = [];
    for (const sub of subs) {
      const events = await checkSubscription(env, sub);
      const dispatched = [];
      for (const ev of events) {
        const ok = await dispatch(env, sub, ev.title, ev.message);
        dispatched.push({ title: ev.title, sent: ok });
      }
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
