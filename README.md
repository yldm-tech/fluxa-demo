# fluxa payment integration demos

[![CI](https://github.com/yldm-tech/fluxa-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/yldm-tech/fluxa-demo/actions/workflows/ci.yml) [![X](https://img.shields.io/badge/X-%40suzukaze__haduki-000000?logo=x&logoColor=white)](https://x.com/suzukaze_haduki) [![GitHub Sponsors](https://img.shields.io/badge/GitHub%20Sponsors-ea4aaa?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/houko)

Working merchant integrations for the [fluxa](https://pay.fluxa.cash) payment API, in 8 languages. Copy `.env.example` to `.env`, fill in three secrets, and run.

**中文文档：[README.zh-CN.md](README.zh-CN.md)** · Integrating with an AI agent? Point it at [AGENTS.md](AGENTS.md).

Every demo does the same three things:

1. **Signs** a merchant API request (HMAC-SHA256)
2. **Creates a charge** and handles the payer instruction
3. **Receives a webhook**: verify signature → decrypt (optional) → process idempotently

---

## Quick start

```bash
cp .env.example .env
$EDITOR .env    # fill in FLUXA_KEY_ID, FLUXA_SECRET, FLUXA_WEBHOOK_SECRET
```

Get the API key and API secret from **https://pay.fluxa.cash/portal** → Developers → API Keys → New Key; get the separate webhook secret from Developers → Webhooks. If support set your initial password, first set your own using the account-email link in Settings → Security to unlock API key creation. Choose **Test** mode to start: test orders move no real money but still fire webhooks, so the whole integration is exercisable safely. The secret is shown once.

Then pick a language:

| Language | Charge | Receive webhooks | Test | Dependencies |
| --- | --- | --- | --- | --- |
| **Node.js** | `cd node && npm run charge` | `npm run webhook` | `npm test` | none (Node ≥18) |
| **Python** | `cd python && python3 src/charge.py` | `python3 src/webhook.py` | `python3 -m unittest discover -s test` | none (Python ≥3.9) ※ |
| **Go** | `cd go && go run ./cmd/charge` | `go run ./cmd/webhook` | `go test ./...` | none (Go ≥1.21) |
| **Java** | `cd java && mvn -q compile exec:java -Dexec.mainClass=cash.fluxa.demo.ChargeDemo` | `… -Dexec.mainClass=cash.fluxa.demo.WebhookDemo` | `mvn test` | Maven + Jackson (JDK 17) |
| **PHP** | `cd php && php src/charge.php` | `php -S 0.0.0.0:9000 src/webhook.php` | `php test/vectors_test.php` | none (PHP ≥8.1) |
| **Ruby** | `cd ruby && ruby lib/charge.rb` | `ruby lib/webhook.rb` | `ruby test/vectors_test.rb` | none ※ |
| **Rust** | `cd rust && cargo run --bin charge` | `cargo run --bin webhook` | `cargo test` | a few crates (Rust 1.85+) |
| **C# / .NET** | `cd dotnet && dotnet run --project FluxaDemo -- charge` | `dotnet run --project FluxaDemo -- webhook` | `dotnet test` | none (.NET 8) |

※ **Encrypted webhooks only** (`WEBHOOK_ENCRYPTION`, off by default). Signing, charging, and plaintext webhooks are unaffected:
> - **Python** needs `pip install cryptography` — the standard library has no AES.
> - **Ruby** needs a Ruby linked against **OpenSSL** (any version). macOS's system ruby links **LibreSSL**, which cannot do AES-256-GCM at all. Not a version issue: the same code passes fully on `ruby:2.6-slim` (Ruby 2.6 + OpenSSL). Use rbenv/homebrew ruby or the `ruby:3.3` image.

Each language directory has its own README with details and Docker one-liners for runtimes you don't have installed.

Verify every language against the signing vectors — no `.env` and no server needed, and Docker fills in for any runtime you're missing:

```bash
./verify-all.sh            # all of them
./verify-all.sh node go    # just these
```

---

## The signing contract

Full reference: **[`spec/SIGNING.md`](spec/SIGNING.md)**. Known-answer vectors: **[`spec/vectors.json`](spec/vectors.json)**, generated from fluxa's actual server-side code.

Requests carry `X-Api-Key`, `X-Timestamp`, and `X-Signature`, where

```
X-Signature = hex(HMAC_SHA256(secret, canonical))
```

and `canonical` is **5 lines** joined with `\n`:

```
METHOD
PATH
CANONICAL_QUERY      ← empty string when there is no query — but the LINE stays
TIMESTAMP
SHA256_HEX(BODY)
```

> **The two mistakes that cost the most time**
>
> 1. **Dropping the empty third line** when a request has no query. That makes it a 4-line string, the HMAC is completely different, and every request fails with `401 bad_signature`.
> 2. **Signing different bytes than you send.** Serialize the body once; sign and send that exact string. Re-serializing changes key order or spacing and the signature dies.

### Verifying webhooks

```
X-Fluxa-Signature = hex(HMAC_SHA256(webhook_secret, "<X-Fluxa-Timestamp>.<raw body>"))
```

Verify against the **raw received bytes** (a re-serialized object will not match), compare in constant time, and check the timestamp for freshness. When payload encryption is enabled the body is an AES-256-GCM envelope — **verify first, then decrypt**; the key is `SHA256(webhook_secret)`.

Deduplicate using `event_id` from the verified body; retries and manual redeliveries preserve it. `X-Fluxa-Event-Id` is for tracing, not a substitute for the authenticated body. Commit the unique event ID and business changes in one database transaction. Events remain unordered: advance cumulative refunds with `max(recorded, refunded_amount)` and settlement-by-received credits with `max(recorded, received_amount)`. The demo memory/file stores are not a production ledger. See [the signing and event contract](spec/SIGNING.md).

---

## Why every language ships a vectors test

The failure mode when porting HMAC across languages is **silent disagreement**: the code runs, a signature comes out, and you only find out it's wrong when the server rejects it. The classic traps:

- Omitting the canonical's empty line when there's no query (4 lines vs 5)
- Sorting the query with the language's default comparator — C#'s is **culture-sensitive**, JavaScript's and Java's are **UTF-16** — while the server sorts by **UTF-8 bytes**
- Signing one byte string and sending another (serializing twice)
- Parsing amounts as floats. `9.99` looks fine on its own, but the error compounds — summing it a hundred times gives `999.0000000000007`, not `999`
- Deduplicating webhooks on `(event, order_id)` and dropping partial refunds

`spec/vectors.json` is generated from fluxa's real signing code, and every language's test suite reproduces it byte for byte. **That is the criterion for a correct port** — it needs no running server and doesn't depend on anyone's reading of the prose.

The suites are mutation-tested: introduce the 4-line canonical bug or a UTF-16 comparator and they fail loudly. See [`spec/README.md`](spec/README.md).

---

## Driving the full flow

```bash
# 1. Create a charge
cd node && npm run charge

# 2. Open the printed redirect_url. On the `mock` channel the checkout page has a
#    "simulate success" button, which drives the order to paid and fires the webhook.

# 3. Receive the webhook — register your callback URL first
#    (Portal → Developers → Webhooks)
npm run webhook
```

Your local receiver isn't reachable from the internet, so use a tunnel (ngrok, Cloudflare Tunnel) and register that public URL as the callback.

### Current charge options

The basic hosted-checkout request remains compatible. Optional request fields can be added to the charge object in any language (Go and Rust expose typed fields):

| Field | Contract |
| --- | --- |
| `network` | Routes a cryptocurrency charge when `channel` is omitted; an explicit channel takes precedence. |
| `method` | Pins a supported sub-method, such as a Stripe method; unsupported combinations can fall back to the channel's offered methods. Do not assume it pins an arbitrary provider. |
| `presentation` | `redirect` (default) or `embedded`. Embedded Stripe returns `client_secret` and `publishable_key` for the Payment Element. |
| `settle_on_received` | Optional boolean, only for on-chain direct settlement. Leave absent for ordinary fiat/LianLian charges. |
| `min_received_amount` | Optional decimal string with settlement by received amount; positive and no greater than `amount`. Omit to use the platform's channel/fee-aware minimum. |
| `metadata` | Arbitrary JSON object. For on-chain payments, provide a stable opaque `customer` ID so a payer can reuse their assigned address. |

On an idempotent replay, omitted settlement/presentation options reuse the original order; explicit conflicting values return `409 idempotency_mismatch`. A replay of an expired, canceled or failed order returns `instruction.type: none`; do not offer `payment.channel_ref` as a payable address. `409 order_closed_during_charge` or `stripe_account_changed_during_charge` requires a new `merchant_order_id`. An unpaid order can be canceled with signed `POST /api/v1/orders/{id}/cancel`. `GET /api/v1/orders/{id}` also exposes `checkout_url`, payment and settlements. API keys are mode-scoped: use the same Test/Live mode when reading or refunding an order.

### LianLian / WeChat Pay

An external merchant integrates with Fluxa using its own Fluxa API key and webhook secret, not the platform's LianLian RSA keys. First complete merchant onboarding and enable the appropriate fiat payment access. Call signed `GET /api/v1/channels` using that merchant's key and select the exact code returned for the enabled LianLian channel. A code such as `lianlian_wechat` is an operator configuration, not a universal constant; do not copy another merchant's configuration blindly.

Set `FLUXA_CHANNEL` to that code, use matching Live credentials for a live channel, and choose a currency/amount supported by that configuration. Replace the example return/cancel URLs in the charge entrypoint with your own site. Keep `presentation` at its default redirect and leave `settle_on_received` absent. Redirect the payer to `instruction.redirect_url`, then confirm payment through the verified callback. Register your own public callback URL and webhook secret. Use `mock` with Test keys to verify the integration before a live payment; it does not exercise LianLian's real payment network.

### Troubleshooting

**`401 bad_signature`** — the canonical string is wrong. Check the empty third line, that you signed the exact bytes you sent, and that `X-Timestamp` matches the signed timestamp. Run your language's test suite: if the vectors pass, your signing is correct and the problem is elsewhere.

**`400 channel_environment_mismatch`** — `FLUXA_CHANNEL` doesn't match your key's mode. A Test key needs a test-environment channel (e.g. `mock`); a Live key needs a live one. This is **not** a signature problem. Run the signed `GET /api/v1/channels` to see what your account can use.

**`401 replayed_request`** — a verified signature is single-use within the clock-skew window. Two identical requests in the same second produce the same signature. Vary the timestamp or the body.

**No webhooks arriving** — check that the callback URL is publicly reachable and registered in the portal, and that only one language's receiver holds `WEBHOOK_PORT`.

**Running a demo in Docker** — `localhost` inside a container is the container itself. Point at the hosted API: `-e FLUXA_BASE_URL=https://pay.fluxa.cash`.

---

## Layout

```
.env.example        one config file, shared by every language
AGENTS.md           integration contract for AI coding agents
spec/
  SIGNING.md        the signing contract
  vectors.json      known-answer vectors from fluxa's real signing code
  README.md         what the vectors cover and why
verify-all.sh       run every language's vectors test
node/ python/ go/ java/ php/ ruby/ rust/ dotnet/
```

## Links

- Merchant portal: https://pay.fluxa.cash/portal
- Documentation: https://docs.fluxa.cash

## License

[MIT](LICENSE) — copy anything here into your own integration.
