// LiveWatch Service Worker — background missed-reward check for PWA installs
const ARB_RPCS = [
  "https://arbitrum-one-rpc.publicnode.com",
  "https://arbitrum.drpc.org",
  "https://arb1.arbitrum.io/rpc",
];
const BONDING_MANAGER = "0x35Bcf3c30594191d53231e4ff333e8a770453e40";
const ROUNDS_MANAGER  = "0xdd6f56DcC28D3F5f27084381fE8Df634985cc39f";
const CACHE_NAME = "livewatch-v1";
const SHELL = ["./", "./manifest.json"];

// ── Install: cache app shell ─────────────────────────────────────────────────
self.addEventListener("install", e => {
  e.waitUntil(
    caches.open(CACHE_NAME)
      .then(c => c.addAll(SHELL).catch(() => {}))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: drop old caches ────────────────────────────────────────────────
self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// ── Fetch: serve shell from cache, network-first for API ────────────────────
self.addEventListener("fetch", e => {
  const url = new URL(e.request.url);
  if (url.origin === self.location.origin && (url.pathname === "/" || url.pathname === "/manifest.json")) {
    e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
  }
});

// ── On-chain helpers ─────────────────────────────────────────────────────────
async function ethCall(to, data) {
  for (const rpc of ARB_RPCS) {
    try {
      const res = await fetch(rpc, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to, data }, "latest"] }),
      });
      if (!res.ok) continue;
      const j = await res.json();
      if (j.error || !j.result) continue;
      return j.result;
    } catch {}
  }
  return null;
}

async function getCurrentRound() {
  const hex = await ethCall(ROUNDS_MANAGER, "0x8a19c8bc");
  if (!hex) return null;
  try { return Number(BigInt(hex)); } catch { return null; }
}

async function getLastRewardRound(orch) {
  const data = "0x1944cb05" + orch.toLowerCase().replace("0x", "").padStart(64, "0");
  const hex = await ethCall(BONDING_MANAGER, data);
  if (!hex) return null;
  const cleaned = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (cleaned.length < 64) return null;
  try { return Number(BigInt("0x" + cleaned.slice(0, 64))); } catch { return null; }
}

// ── State ────────────────────────────────────────────────────────────────────
let walletData = null; // { wallet, orchAddr, orchName }
let lastAlertedMissedRound = 0;
let lastAlertedClaimedRound = 0;

async function checkMissedReward() {
  if (!walletData?.orchAddr) return;
  const { orchAddr, orchName } = walletData;
  const [current, lastReward] = await Promise.all([
    getCurrentRound().catch(() => null),
    getLastRewardRound(orchAddr).catch(() => null),
  ]);
  if (current == null || lastReward == null) return;

  const missed = lastReward < current;
  if (missed && lastAlertedMissedRound !== current) {
    lastAlertedMissedRound = current;
    await self.registration.showNotification("🔴 LiveWatch — Round Not Claimed", {
      body: `${orchName} hasn't called reward() for round ${current}`,
      tag: "lw-missed-reward",
      icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' fill='%23050a0e'/%3E%3Ccircle cx='32' cy='32' r='12' fill='%2300e5a0'/%3E%3C/svg%3E",
      badge: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' fill='%23050a0e'/%3E%3Ccircle cx='32' cy='32' r='12' fill='%2300e5a0'/%3E%3C/svg%3E",
      data: { url: self.location.origin },
    });
  } else if (!missed && lastAlertedMissedRound > 0 && lastAlertedClaimedRound !== current) {
    lastAlertedClaimedRound = current;
    lastAlertedMissedRound = 0;
    await self.registration.showNotification("✅ LiveWatch — Reward Claimed", {
      body: `${orchName} claimed rewards for round ${current}`,
      tag: "lw-missed-reward",
      data: { url: self.location.origin },
    });
  }
}

// ── Message from main thread ─────────────────────────────────────────────────
self.addEventListener("message", e => {
  if (e.data?.type === "UPDATE_WALLET") {
    walletData = e.data;
    checkMissedReward(); // immediate check on wallet load
  }
  if (e.data?.type === "CLEAR_WALLET") {
    walletData = null;
    lastAlertedMissedRound = 0;
    lastAlertedClaimedRound = 0;
  }
});

// ── Periodic Background Sync (Chrome/Android when installed as PWA) ──────────
self.addEventListener("periodicsync", e => {
  if (e.tag === "lw-missed-reward") {
    e.waitUntil(checkMissedReward());
  }
});

// ── Notification click: open or focus the app ────────────────────────────────
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const target = e.notification.data?.url || self.location.origin;
  e.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true }).then(list => {
      const existing = list.find(c => c.url.startsWith(target));
      if (existing) return existing.focus();
      return clients.openWindow(target);
    })
  );
});
