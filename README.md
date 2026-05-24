# LiveWatch — Livepeer Delegator Monitor

Real-time monitoring for Livepeer delegators. Get notified on Telegram (or browser) when your orchestrator changes reward cuts, misses a reward round, or claims inflation rewards.

**Live app:** [livewatcher.xyz](https://livewatcher.xyz)

---

## Features

- **Multi-wallet tracking** — add any number of delegator wallets
- **Orchestrator dashboard** — reward cut, fee cut, total stake, 30-day economics
- **Cut change history** — table of all reward/fee cut changes with timestamps
- **Alerts panel** — in-app alert feed with change detection on every sync
- **Network context** — active orchestrators, total LPT staked, 24h payouts/rewards, treasury balance — all with 30-day sparklines and drill-down charts
- **Telegram notifications** — 24/7 background alerts via bot:
  - Reward cut changed
  - Fee cut changed
  - Round not claimed (missed reward)
  - Detailed per-round claim reports with LPT/USD breakdown and your share
- **Browser notifications** — desktop/mobile popups while page is open
- **PWA support** — install as app (Add to Home Screen); Android Chrome gets background missed-reward checks via Periodic Background Sync
- **CSV export** — download reward events and cut history for any time range (30d / 90d / 180d / 1yr / all time)
- **Nicknames** — label wallets for easier identification
- **Telegram Login** — sync subscriptions across devices

---

## Architecture

```
frontend/
  index.html      Single-file React app (no build step, React via CDN)
  sw.js           Service worker for PWA offline + background notifications
  manifest.json   PWA manifest

backend/
  worker.js       Cloudflare Worker — REST API + cron every 30 minutes
  wrangler.toml   Worker config (KV namespaces, cron trigger)
```

**Data sources:**
- [Livepeer Network API](https://livepeer-network-api.cloudspe.com/api/v1) — delegator/orchestrator data, events, economics
- Arbitrum One RPC (public) — on-chain round and reward state via `eth_call`
- Telegram Bot API — notification delivery

**Storage (Cloudflare KV):**
- `SUBS` — subscriptions, user records, nicknames, treasury snapshots
- `SNAP` — per-subscription state snapshots for change detection
- `CODES` — short-lived Telegram linking codes (10-minute TTL)

---

## Backend Deployment

### Prerequisites
- Cloudflare account with Workers enabled
- Telegram bot (create via [@BotFather](https://t.me/BotFather))

### Steps

**1. Create KV namespaces**
```bash
cd backend
npx wrangler kv namespace create SUBS
npx wrangler kv namespace create SNAP
npx wrangler kv namespace create CODES
```
Update the IDs in `wrangler.toml`.

**2. Set secrets**
```bash
npx wrangler secret put TELEGRAM_BOT_TOKEN
```

**3. Update `wrangler.toml`**
```toml
[vars]
TELEGRAM_BOT_USERNAME = "YourBotUsername"   # no @
```

**4. Deploy**
```bash
CLOUDFLARE_API_TOKEN=your_token npx wrangler deploy
```

**5. Set Telegram webhook**
```
https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://your-worker.workers.dev/telegram/webhook
```

### Debug endpoints

After deployment you can manually trigger checks without waiting for cron:

```bash
# Run check for a specific wallet (fires real notifications)
curl -X POST "https://your-worker.workers.dev/debug/trigger?wallet=0x..."

# Inspect stored snapshot for a subscription
curl "https://your-worker.workers.dev/debug/snap?wallet=0x..."
```

---

## Frontend Deployment

Static HTML — no build step. Host anywhere (GitHub Pages, Cloudflare Pages, S3, etc.).

The `API_BASE` (Livepeer API) and backend worker URL are hardcoded in `index.html`. Update `getBackend()` if you deploy your own worker:

```js
function getBackend() { return "https://your-worker.workers.dev"; }
```

For Telegram Login Widget to work, run `/setdomain` in @BotFather and enter your frontend domain.

---

## Notification Types

| Type | Trigger | Telegram | Browser |
|------|---------|----------|---------|
| Reward cut changed | Orchestrator updates reward cut % | ✓ | ✓ |
| Fee cut changed | Orchestrator updates fee cut % | ✓ | ✓ |
| Round not claimed | `lastRewardRound < currentRound` on-chain | ✓ | ✓ |
| Round claimed (resolution) | Orch catches up after missed round | ✓ | ✓ |
| Claim report | New `Reward` event detected | ✓ | ✓ |

Cron runs every **30 minutes**. Missed-reward alerts have a 35-minute cooldown per round to prevent double-alerting within one cron cycle.

---

## CSV Export

Click **⬇ Export CSV** (appears after loading a wallet). Choose:
- **Time period**: 30d / 90d / 180d / 1 year / All time
- **Reward Events** (`livewatch_rewards_*.csv`):
  `Round, Date, Block, Total LPT Minted, Orch Cut %, Orch Share LPT, Delegators Share LPT, Your Stake %, Your Share LPT, LPT Price USD, Total USD, Orch USD, Delegators USD, Your Share USD`
- **Cut History** (`livewatch_cuts_*.csv`):
  `Date, Block, Event ID, Reward Cut %, Fee Cut %, Fee Share %`

Your share is estimated proportionally (your bonded / total orch stake × delegators portion) using your current stake snapshot.

---

## Local Development

No build toolchain required. Open `frontend/index.html` directly in a browser, or serve with any static server:

```bash
cd frontend
npx serve .
# or
python3 -m http.server 8080
```

For the backend worker locally:
```bash
cd backend
npx wrangler dev
```

---

## License

MIT
