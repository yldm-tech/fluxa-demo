# fluxa demo — Node.js

Zero dependencies: only Node's built-in `node:crypto` / `fetch` / `node:http`.

Signs merchant API requests, creates charges, and receives verified webhooks. The signing
contract is [`../spec/SIGNING.md`](../spec/SIGNING.md), pinned by
[`../spec/vectors.json`](../spec/vectors.json) — known-answer vectors generated from fluxa's
actual server-side signing code.

## Prerequisites

- **Node ≥ 18** (for built-in `fetch`). No `npm install` — there are no dependencies.
- Config comes from one `.env` in the repo root, **shared by every language demo**:

  ```bash
  cd ..
  cp .env.example .env
  $EDITOR .env     # fill in FLUXA_KEY_ID / FLUXA_SECRET / FLUXA_WEBHOOK_SECRET
  ```

  Get the keys from the merchant portal at **https://pay.fluxa.cash/portal** → Developers →
  API Keys → New Key. Choose **Test** mode to start: test orders move no real money but still
  fire webhooks, so you can exercise the whole integration safely. The secret is shown once.

  Real environment variables win over `.env`, so `FLUXA_CHANNEL=stripe npm run charge`
  overrides it for one run.

## Run

All commands run from this directory (`node/`).

```bash
npm run charge                 # create a charge
npm run charge my-order-1      # ...with your own merchant_order_id (it is the idempotency key)
npm run webhook                # receive webhook callbacks (in another terminal)
npm test                       # check against ../spec/vectors.json
```

`npm run charge` creates a charge, prints the payer instruction based on `instruction.type`
(redirect / crypto address / client_secret / none), then reads the order back.

`npm run webhook` listens on `:9000` by default (`WEBHOOK_PORT` in `.env`) and does
verify → decrypt (if enabled) → deduplicate → 2xx. Your callback URL must be publicly
reachable, so use a tunnel (ngrok, Cloudflare Tunnel) and register that URL in the portal.

`npm test` needs no server and no credentials.

### Without Node installed

```bash
docker run --rm -v "$PWD/..":/app -w /app/node node:22-slim node --test "test/*.test.js"
```

Swap `node --test "test/*.test.js"` for `node src/charge.js` to charge from the container.
Note that `localhost` inside a container is the container itself — point at the hosted API
with `-e FLUXA_BASE_URL=https://pay.fluxa.cash`.

## Files

| File | Purpose |
| --- | --- |
| `src/fluxa.js` | Signing + client + webhook verify/decrypt. **This is the file to copy** |
| `src/config.js` | Reads the shared `../../.env` (real env vars win) |
| `src/charge.js` | Charge → print payer instruction → read the order back |
| `src/webhook.js` | Webhook receiver: verify → decrypt → deduplicate → 2xx |
| `test/vectors.test.js` | Checks against `../spec/vectors.json` |
| `test/dedupe.test.js` | Pins the refund idempotency key |

## Integrating into your own project

Copy `src/fluxa.js` — it stands alone and does not depend on `config.js`:

```js
import { createCharge, verifyWebhook } from "./fluxa.js";

const cfg = { baseUrl: "https://pay.fluxa.cash", keyId: "pk_…", secret: "sk_…" };

const { order, instruction } = await createCharge(cfg, {
  merchant_order_id: "your-order-123",   // idempotency key
  amount: "9.99",                         // string, never a float
  currency: "USD",
  channel: "mock",
});
// instruction.type === "redirect" → send the payer to instruction.redirect_url
```

On the webhook side (Express — note the **raw body**):

```js
app.post("/fluxa/webhook", express.raw({ type: "*/*" }), (req, res) => {
  const raw = req.body.toString("utf8");
  if (!verifyWebhook(WEBHOOK_SECRET, req.headers["x-fluxa-timestamp"], raw, req.headers["x-fluxa-signature"])) {
    return res.status(401).end();
  }
  const evt = JSON.parse(raw);
  // The idempotency key must include refunded_amount. (event, order_id) is NOT unique:
  // an order can be partially refunded more than once, and deduplicating on that pair
  // silently drops the second partial refund. See ../spec/SIGNING.md §3.1.
  const key = `${evt.event}:${evt.order_id}:${evt.refunded_amount ?? ""}`;
  // …process idempotently by key, and return 2xx quickly
  res.status(200).end();
});
```

`express.json()` parses the body first, and re-serializing it with `JSON.stringify` does not
reliably reproduce the received bytes (key order, spacing, Unicode escaping), so verification
fails — **you must verify against the raw bytes**.

## Gotchas

- **Amounts are always strings.** Parsing `9.99` as a double does not visibly corrupt it — but
  the nearest double is `9.99000000000000021…`, and the error compounds: summing `9.99` a
  hundred times gives `999.0000000000007`, not `999`. The server stores `numeric(38,18)` and
  uses decimal arithmetic.
- **The signed body must be the exact bytes you send** — `fluxa.js` calls `JSON.stringify`
  exactly once and both signs and sends that same string.
- **Sort query fragments by UTF-8 bytes, not with `arr.sort()`.** JavaScript's default sort
  compares UTF-16 code units, which disagrees with the server for code points above U+FFFF.
  `fluxa.js` compares `Buffer.from(s, "utf8")` with `Buffer.compare`.
- **The canonical is 5 lines**, and with no query the third line is an empty line that must
  still be there — drop it and every request fails with `401 bad_signature`.

Full details: [`../spec/SIGNING.md`](../spec/SIGNING.md).
