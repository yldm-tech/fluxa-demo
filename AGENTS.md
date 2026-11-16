# Integrating fluxa — contract for AI coding agents

You are writing a merchant integration against the fluxa payment API. This file is the contract. Follow it exactly and the integration works on the first try. Deviate on any point marked **MUST** and it fails — usually silently, or with `401 bad_signature`.

This contract is self-sufficient: it has been validated by building a working integration from it alone, with every vector in §4 passing. Read it start to finish before writing code.

---

## 1. Request signing — MUST

Three headers on every `/api/v1/*` request:

```
X-Api-Key:    <key_id>            e.g. pk_test_...
X-Timestamp:  <unix seconds>      server allows ±300s skew
X-Signature:  hex(HMAC_SHA256(secret, canonical))    lowercase hex
```

`canonical` is **exactly 5 lines** joined with `\n`:

```
line 1: METHOD              uppercased
line 2: PATH                no host, no query. e.g. /api/v1/charges
line 3: CANONICAL_QUERY     see §1.1 — EMPTY STRING when there is no query
line 4: TIMESTAMP           byte-identical to the X-Timestamp header
line 5: SHA256_HEX(BODY)    lowercase hex of the raw body bytes
```

**MUST: when there is no query, line 3 is an empty string but THE LINE STILL EXISTS.** The canonical for a bodyless-query POST is:

```
"POST\n/api/v1/charges\n\n1750000000\n74f74511aebc..."
                       ^^ this empty line
```

Producing a 4-line string here is the single most common integration failure. It yields a completely different HMAC and the server returns `401 bad_signature` for **every** request, not just ones with a query.

An empty body hashes the empty string: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

### 1.1 CANONICAL_QUERY — MUST

Split the raw query on `&`, sort fragments in **UTF-8 byte order**, join with `&`. Empty query → empty string.

```
""                     → ""
"status=paid&limit=10" → "limit=10&status=paid"
"limit=10&status=paid" → "limit=10&status=paid"
"z=1&z=2&a=3"          → "a=3&z=1&z=2"
```

Sort whole `key=value` fragments, not by key. Do not percent-decode. Keep duplicate keys.

**MUST use a UTF-8 byte comparator.** Language defaults are wrong in ways that pass every ASCII test and fail in production:

| Language | Wrong (default) | Correct |
| --- | --- | --- |
| JavaScript | `arr.sort()` — UTF-16 | compare `Buffer.from(s,'utf8')` with `Buffer.compare` |
| Java | `String.compareTo` — UTF-16 | `Arrays.compareUnsigned(a.getBytes(UTF_8), b.getBytes(UTF_8))` |
| C# | `Array.Sort(arr)` — **culture-sensitive** | compare UTF-8 `byte[]`; `StringComparer.Ordinal` at minimum |
| Python | — | `key=lambda s: s.encode("utf-8")` |
| PHP | `sort($a)` — `SORT_REGULAR` compares numeric-looking fragments numerically | `sort($a, SORT_STRING)` |
| Ruby | — | `Array#sort` is fine |
| Go, Rust | — | `sort.Strings` / `sort()` are already byte order |

**MUST keep trailing empty fragments when splitting.** Ruby's default `split` and Java's one-arg `String.split` drop them, diverging from the server. Both need an explicit `-1` limit.

### 1.2 Sign the exact bytes you send — MUST

Serialize the body **once**. Sign that string and send that same string. Do not serialize, sign, then serialize again — different key order or whitespace produces a different hash and the signature dies.

```js
const body = JSON.stringify(payload);          // once
const sig  = sign(secret, canonical(..., body));
fetch(url, { body });                          // the same string
```

### 1.3 Amounts — MUST

Amounts are **decimal strings** everywhere, in both directions. The server stores `numeric(38,18)` and uses decimal arithmetic.

**MUST NOT** parse them into float/double/f64. Parsing `9.99` as a double does not visibly corrupt it — but the nearest double is `9.99000000000000021…`, and the error compounds: summing `9.99` a hundred times gives `999.0000000000007`, not `999`. Reconciliation then fails by a cent that no one can find. Use the string as-is, or a decimal type (`BigDecimal`, `decimal`, `Decimal`, `rust_decimal`) if you must compute.

---

## 2. Creating a charge

```
POST /api/v1/charges
```

```json
{
  "merchant_order_id": "your-order-123",
  "amount": "9.99",
  "currency": "USD",
  "channel": "mock",
  "subject": "optional title",
  "metadata": {"any": "json"},
  "return_url": "https://you.example/success",
  "cancel_url": "https://you.example/cancel",
  "expires_in_seconds": 1800
}
```

- `merchant_order_id` is the **idempotency key**. Re-sending the same value returns the same order with `"idempotent": true` — it does not create a second charge.
- `channel`'s environment **MUST** match your key's mode, or you get `400 channel_environment_mismatch` (this is not a signature error). Test key → test channel (e.g. `mock`); live key → live channel. Call the signed `GET /api/v1/channels` to enumerate.

The `201` response is `{order, payment, instruction, idempotent}`. Branch on `instruction.type`:

| `instruction.type` | What to do |
| --- | --- |
| `redirect` | send the payer to `instruction.redirect_url` |
| `crypto_address` | show `deposit_address`, `amount_due`, `chain`, `asset`, `required_confirmations` |
| `client_secret` | initialize Stripe.js with `instruction.publishable_key` and confirm using `instruction.client_secret` |
| `none` | inspect `order.status`; a closed replay is not payable and needs a new merchant order ID |

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

Other endpoints: `GET /api/v1/orders/{id}`, `GET /api/v1/orders?status=paid&limit=10`, `POST /api/v1/orders/{id}/refund`, `POST /api/v1/orders/{id}/cancel`, `GET /api/v1/me`, `GET /api/v1/channels`, `GET /api/v1/wallets`.

---

## 3. Receiving webhooks

```
X-Fluxa-Event:      <event type>
X-Fluxa-Event-Id:   <same opaque ID as body event_id>
X-Fluxa-Timestamp:  <unix seconds>
X-Fluxa-Signature:  hex(HMAC_SHA256(webhook_secret, "<timestamp>.<raw body>"))
X-Fluxa-Encryption: A256GCM        (only when payload encryption is enabled)
```

`webhook_secret` is a **different secret** from the API secret.

### MUST: verify against the raw bytes

```
expected = hex(HMAC_SHA256(webhook_secret, timestamp + "." + rawBody))
reject unless constant_time_equals(expected, header)
```

**MUST NOT** verify against a re-serialized object. Frameworks that auto-parse JSON destroy the raw bytes — capture them first:

```js
// Express: express.raw(), NOT express.json()
app.post("/fluxa/webhook", express.raw({ type: "*/*" }), (req, res) => {
  const raw = req.body.toString("utf8");     // exact received bytes
  ...
});
```

**MUST** use a constant-time comparison (`timingSafeEqual`, `hash_equals`, `compare_digest`, `hmac.Equal`, `CryptographicOperations.FixedTimeEquals`, `MessageDigest.isEqual`).

Guard the length first. Several of those **throw** rather than return false when the inputs differ in length — Node's `timingSafeEqual` raises `RangeError: Input buffers must have the same byte length`, and .NET's `FixedTimeEquals` needs equal spans. A missing or truncated `X-Fluxa-Signature` is attacker-controlled, so an unguarded compare turns into a 500 instead of a clean 401:

```js
const a = Buffer.from(expected, "utf8");
const b = Buffer.from(provided ?? "", "utf8");
return a.length === b.length && timingSafeEqual(a, b);   // length check FIRST
```

Comparing lengths is not a leak: the expected signature's length is a constant (64 hex chars).

**SHOULD** reject stale timestamps (±300s) after the signature check, to limit replay.

**SHOULD** return `2xx` fast. Non-2xx is retried with exponential backoff, up to 8 attempts.

### 3.1 Event identity and state — MUST

Every event carries a nonempty string `event_id` in its signed body and the same value in `X-Fluxa-Event-Id`. Verify raw bytes, decrypt if enabled, then use the body ID as the unique key. HTTP headers are not signed, so never substitute the header for a missing body ID. Reject missing/malformed IDs. Retries/manual redeliveries keep the ID; different events have different IDs, even when their type, order and amounts match. Never reconstruct an identity from `(event, order_id, refunded_amount)`.

Production MUST insert the unique event ID and apply business changes in one transaction, returning 2xx only after commit (or durable enqueue). Roll back both on failure so a retry can succeed. The demo local stores are not production storage.

IDs do not establish order. Refunds carry cumulative `refunded_amount`: apply only the positive increase to `max(recorded, refunded_amount)`, using decimals. Settlement-by-received orders carry `settle_on_received: true` and cumulative `received_amount`; apply the same atomic max/delta rule for both `payment.succeeded` and `payment.additional_received`, which may arrive in either order. Never separately add `deposit_amount`. Do not apply max to `fee` / `net` snapshots, which can decrease after refunds.

`payment.pending` and `order.*` are not payment confirmations; close payment instructions on `order.expired` / `order.canceled` and never let a late pending/created event reopen a paid/closed order. Track disputes by `dispute_id`: preserve `escalated` and `corrected`, allow closed before created, and let a corrected won replace lost. Dispute events alone do not change balances. Settlement/subscription events must not duplicate payment fulfillment. Unknown events may be acknowledged without fulfillment; non-payment events can omit order fields. Check `is_test` before any real fulfillment or balance mutation.

Explicitly subscribe to `order.*`, `payment.pending`, and `payment.dispute_*`; an empty subscription list excludes them. A nonempty list must include all needed events, including `payment.additional_received` for settlement by received amount. Full event and field reference: [SIGNING.md §3.2](spec/SIGNING.md#32-current-events-and-ordering).

### 3.2 Encrypted payloads (optional)

When enabled, the body is an envelope and `X-Fluxa-Encryption: A256GCM` is set:

```json
{ "alg": "A256GCM", "data": "<base64( nonce[12] || ciphertext || gcm_tag[16] )>" }
```

**MUST verify the signature BEFORE decrypting** — it covers the envelope as sent.

```
key    = SHA256(webhook_secret)          32 bytes, over the secret's raw bytes
blob   = base64_decode(data)
nonce  = blob[:12]
plain  = AES_256_GCM_open(key, nonce, blob[12:], aad=nil)
```

Tag handling differs by language — a frequent porting bug:

| Language | Tag |
| --- | --- |
| Go, Java, Rust | stays appended; pass `blob[12:]` whole (Java: `GCMParameterSpec(128, nonce)`) |
| Node, Ruby, PHP, C# | passed separately: tag = `blob[-16:]`, ciphertext = `blob[12:-16]` |

AAD is empty.

---

## 4. Verify your work — do not skip

`spec/vectors.json` holds known-answer vectors generated from fluxa's **actual server-side signing code**. Your implementation **MUST** reproduce them byte for byte. This is the acceptance test, and it needs no server and no credentials.

Assert, at minimum:
- every `requests[]` entry: your `canonical` **and** your `signature` match exactly
- every `webhooks[]` entry: your signature matches; and that a tampered body, a wrong secret, and an empty signature are all rejected
- every `envelopes[]` entry: decrypts to the expected plaintext
- the no-query canonical is 5 lines with an empty 3rd
- reordering a query does not change the signature, but tampering with a value does
- `get_query_utf16_divergence` — this is the only vector that catches a wrong sort comparator. Every other query vector is ASCII, where all comparators agree.

Then check your suite actually has teeth. Run **both** mutations, restoring after each:

1. **Drop the CANONICAL_QUERY line** from your canonical → most request vectors must fail. This catches structural breakage, but it is blunt: it reds nearly everything regardless of how good your comparator is.
2. **Swap your byte comparator for the language default** (`arr.sort()`, `String.compareTo`, `Array.Sort`) → **`get_query_utf16_divergence` must fail, and only it**. This is the sharp one. It is the exact failure mode §1.1's table exists to prevent, and the one an ASCII-only suite hides — if your suite stays green here, it is not testing the comparator at all.

A suite that survives either mutation is asserting nothing about the signature.

---

## 5. Configuration

All demos read one `.env` at the repo root. Real environment variables take precedence over the file.

```
FLUXA_BASE_URL=https://pay.fluxa.cash
FLUXA_KEY_ID=pk_test_...
FLUXA_SECRET=sk_test_...          # signs requests; never leaves your server
FLUXA_WEBHOOK_SECRET=whsec_...    # verifies callbacks; a DIFFERENT secret
FLUXA_CHANNEL=mock
```

Keys come from https://pay.fluxa.cash/portal → Developers → API Keys. The secret is shown once.

**MUST NOT** commit `.env`, log the secrets, or send either secret to the browser. The API secret signs on your server only.

---

## 6. Checklist before you call it done

The whole document matters, but these are the ones that pass every naive test and fail in production — the rest of your suite will catch the others:

- [ ] Query sorted by **UTF-8 bytes**, not the language default. Every ASCII vector passes either
      way; only `get_query_utf16_divergence` catches it.
- [ ] `split` on `&` keeps trailing empty fragments (Ruby/Java need an explicit `-1`)
- [ ] Idempotency uses verified body `event_id`; missing/invalid IDs are rejected, and business changes commit atomically with the unique ID
- [ ] The refunded total advances to `max(recorded, incoming)` — never added, never assigned
- [ ] `is_test` checked before fulfilling
- [ ] Constant-time compare guarded by a length check first, or an empty signature throws
- [ ] Mutation check: your tests **fail** when you (a) remove the CANONICAL_QUERY line and
      (b) swap the byte comparator for the language default. Green under either means your suite
      is asserting nothing.

---

## 7. Reference implementations

Once your own implementation passes §4, these are worth a read — each is standalone, dependency-light, and verified against the same vectors:

`node/src/fluxa.js`, `python/src/fluxa.py`, `go/fluxa/fluxa.go`, `java/src/main/java/cash/fluxa/demo/Fluxa.java`, `php/src/Fluxa.php`, `ruby/lib/fluxa.rb`, `rust/src/lib.rs`, `dotnet/FluxaDemo/Fluxa.cs`.

Their webhook receivers (`*/webhook.*`) show the event identity and cumulative-state guidance from §3.1, and each language's `test/` directory has a vectors suite you can copy as your starting point.
