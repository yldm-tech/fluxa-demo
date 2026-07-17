# fluxa signing contract

This is the authoritative reference for every demo in this repo. It is pinned by
[`vectors.json`](./vectors.json) — known-answer vectors generated from fluxa's actual
server-side signing code. If an implementation disagrees with this document, the vectors decide.

Chinese version: [SIGNING.zh-CN.md](./SIGNING.zh-CN.md)

---

## 1. Signing a merchant API request

Every `/api/v1/*` request carries three headers:

| Header | Value |
| --- | --- |
| `X-Api-Key` | your `key_id` |
| `X-Timestamp` | Unix seconds (the server allows ±5 minutes of clock skew) |
| `X-Signature` | `hex(HMAC_SHA256(secret, canonical))`, lowercase |

### The canonical string is 5 lines, joined with `\n`

```
METHOD
PATH
CANONICAL_QUERY
TIMESTAMP
SHA256_HEX(BODY)
```

- `METHOD` — uppercased (`post` → `POST`)
- `PATH` — no host, no query, e.g. `/api/v1/charges`
- `CANONICAL_QUERY` — see below. **With no query this line is the empty string, but the line is
  still there** — the canonical carries an empty third line
- `TIMESTAMP` — byte-identical to the `X-Timestamp` header
- `SHA256_HEX(BODY)` — SHA-256 of the raw request body bytes, lowercase hex. An empty body hashes
  the empty string (always `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`)

> **The most common mistake: dropping the third line when there is no query.** That yields a
> 4-line string whose HMAC is completely different, and the server rejects it with
> `401 bad_signature`. The line is load-bearing even when empty.

A POST with no query looks like this (`⏎` marks a newline):

```
POST⏎/api/v1/charges⏎⏎1750000000⏎74f74511aebc…
                      ↑ this empty line must be present
```

### CANONICAL_QUERY

Split the raw query on `&`, sort the fragments in **UTF-8 byte order**, join with `&`:

| Raw query | CANONICAL_QUERY |
| --- | --- |
| (none) | `` (empty string) |
| `status=paid&limit=10` | `limit=10&status=paid` |
| `limit=10&status=paid` | `limit=10&status=paid` |
| `z=1&z=2&a=3` | `a=3&z=1&z=2` |

Sort whole `key=value` fragments (not by key alone). Do not percent-decode. Keep duplicate keys.
This makes the signature independent of parameter order while still preventing any parameter from
being tampered with under a captured signature.

Two portability traps, both real:

- **Sort by UTF-8 bytes.** For ASCII/percent-encoded queries — all real traffic — this matches
  most languages' default string sort. It diverges for raw non-ASCII above U+FFFF, and C#'s
  default sort is culture-sensitive, which is wrong even for ASCII in some locales. See
  [`README.md`](./README.md) for the correct comparator per language.
- **Keep trailing empty fragments when splitting.** Ruby's default `split` and Java's one-arg
  `String.split` drop them; both need an explicit `-1` limit to match the server.

### Sign the exact bytes you send

Serialize the body once, then sign and send **that same byte string**. Do not re-serialize after
signing — any difference in key order or whitespace invalidates the signature.

---

## 2. Verifying a webhook

fluxa POSTs an event to your configured callback URL when an order changes state.

| Header | Value |
| --- | --- |
| `X-Fluxa-Event` | `payment.succeeded` / `payment.failed` / `payment.refunded` |
| `X-Fluxa-Timestamp` | Unix seconds |
| `X-Fluxa-Signature` | `hex(HMAC_SHA256(webhook_secret, "<timestamp>.<raw body>"))` |
| `X-Fluxa-Encryption` | present only when payload encryption is on; value `A256GCM` |

To verify:

```
expected = hex(HMAC_SHA256(webhook_secret, X-Fluxa-Timestamp + "." + rawBody))
reject unless constant_time_equals(expected, X-Fluxa-Signature)
```

Rules:

- **Verify against the raw received bytes.** Deserializing and re-serializing changes the bytes and
  the signature will not match. Frameworks that auto-parse JSON (Express's `express.json()`,
  and friends) will break this unless you capture the raw body.
- Use a **constant-time** comparison.
- Check `X-Fluxa-Timestamp` freshness (±5 minutes is a reasonable window) to limit replay.
- Delivery is **at-least-once** — the same event can arrive more than once. Handle it idempotently.
  **Key on `(event, order_id, refunded_amount)`, not `(event, order_id)`** — the latter is not
  unique and will drop partial refunds. See §3.1.
- Failures are retried with exponential backoff (up to 8 attempts). Return `2xx` quickly; anything
  else counts as a failure.

### The encrypted envelope (when payload encryption is enabled)

The body is no longer the plaintext event JSON but:

```json
{ "alg": "A256GCM", "data": "<base64( nonce[12] || ciphertext || gcm_tag[16] )>" }
```

**Verify the signature first, then decrypt** — the signature covers the envelope as sent.

1. `key = SHA256(webhook_secret)` (32 bytes, hashing the secret's **raw bytes**)
2. `blob = base64_decode(json.data)`
3. `nonce = blob[:12]`, `ciphertext_and_tag = blob[12:]`
4. `plaintext = AES_256_GCM_open(key, nonce, ciphertext_and_tag, aad=nil)`

How the tag is passed differs per language — the most common porting mistake here:

| Language | Tag handling |
| --- | --- |
| Go, Java, Rust | tag stays **appended** to the ciphertext; pass `blob[12:]` whole (Java needs `GCMParameterSpec(128, nonce)` — the tag length must be 128 bits) |
| Node, Ruby, PHP, C# | tag is passed **separately**: tag is `blob[-16:]`, ciphertext is `blob[12:-16]` |
| Python | no AES in the standard library — `pip install cryptography` (only needed for encrypted webhooks) |

The AAD is empty.

> **Ruby note:** AES-256-GCM does not work at all on a Ruby linked against **LibreSSL** — which is
> what macOS ships as the system ruby. Every variation fails (setting or omitting `auth_data`,
> reordering `auth_tag`, an explicit `iv_len`). This is a LibreSSL limitation, not a Ruby-version
> one: the identical code passes fully on `ruby:2.6-slim` (Ruby 2.6 + OpenSSL). Use a Ruby built
> against OpenSSL — any version. Signing, charging, and plaintext webhook verification all work
> fine on the system ruby; only the encrypted envelope is affected.

---

## 3. The event body

```json
{
  "event": "payment.succeeded",
  "order_id": "ord_…",
  "merchant_order_id": "order-1",
  "amount": "9.99",
  "currency": "USD",
  "status": "paid",
  "channel": "mock",
  "channel_name": "Mock (test)",
  "is_test": false,
  "refunded_amount": "0"
}
```

| Field | Meaning |
| --- | --- |
| `event` | `payment.succeeded` / `payment.failed` / `payment.refunded` |
| `order_id` | fluxa's order id, `ord_<ULID>` |
| `merchant_order_id` | the idempotency key you supplied at charge time |
| `amount` | the **order total** — not the refunded amount |
| `currency` | currency code |
| `status` | `paid` / `failed` / `refunded` / **`partially_refunded`** |
| `channel` | channel code |
| `channel_name` | channel display name |
| `is_test` | **`true` = a test order with no real money — do not ship goods.** Test-key orders do fire webhooks, so you can exercise your integration |
| `refunded_amount` | **cumulative** refunded total; **present only once something has been refunded**. See §3.1 |

Amounts are always **decimal strings**. Never parse them as floats — the server stores
`numeric(38,18)` and uses decimal arithmetic. Parsing `9.99` as a double does not visibly corrupt it — but the nearest double is `9.99000000000000021…`, and the error compounds: summing `9.99` a hundred times gives `999.0000000000007`, not `999`. Reconciliation then fails by a cent that no one can find.

### 3.1 Partial refunds — where the money goes missing

A single order can be **partially refunded more than once**, and each refund fires its own
`payment.refunded`. Therefore:

> **`(event, order_id)` is not unique.** Deduplicating on it drops the second partial refund as a
> "duplicate", returns `2xx`, and fluxa records the delivery as successful and never retries. The
> customer is under-refunded and nothing errors anywhere in the chain.

Refund 30 then 20 against a 1000 order and you receive two events:

| # | `amount` (order total) | `refunded_amount` (cumulative) | `status` |
| --- | --- | --- | --- |
| 1 | `1000.00` | `30.00` | `partially_refunded` |
| 2 | `1000.00` | `50.00` | `partially_refunded` |

Two rules follow:

1. **Put `refunded_amount` in the idempotency key**: `(event, order_id, refunded_amount)`. The
   values are cumulative and strictly increasing, so the key separates a redelivery of the same
   event (same value → deduplicate) from a genuinely new partial refund (higher value → process).
   Build your database unique index on those three columns too.
2. **Advance your recorded total to `max(recorded, refunded_amount)`.** Never add, and never
   assign blindly:
   - **Adding** over-refunds on a redelivery.
   - **Assigning** regresses on a reorder. At-least-once says nothing about *order*, and deliveries
     are not serialized per order — a failed delivery is retried after a backoff, so the event
     carrying `30` can land *after* the one carrying `50`. A late `30` is not a duplicate — it is a
     different key, so it is correctly processed — and assigning would drop your total from 50 back
     to 30.
   - **Taking the max** is idempotent *and* order-safe, which is why it is the only correct rule.

   Compare the values as decimals, not floats and not strings — `"9.90" > "10.00"` is true
   lexicographically.

   And do not compute a refund from `amount`: that reads "1 refunded on a 1000 order" as
   "1000 refunded".

There is no separate delivery-id header to key on (fluxa sends only `X-Fluxa-Event`,
`X-Fluxa-Timestamp`, `X-Fluxa-Signature`, and `X-Fluxa-Encryption`), so the cumulative-state
semantics above are the only correct approach.
