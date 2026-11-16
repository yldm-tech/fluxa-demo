# fluxa signing contract

This is the authoritative reference for every demo in this repo. It is pinned by [`vectors.json`](./vectors.json) — known-answer vectors generated from fluxa's actual server-side signing code. If an implementation disagrees with this document, the vectors decide.

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
- `CANONICAL_QUERY` — see below. **With no query this line is the empty string, but the line is still there** — the canonical carries an empty third line
- `TIMESTAMP` — byte-identical to the `X-Timestamp` header
- `SHA256_HEX(BODY)` — SHA-256 of the raw request body bytes, lowercase hex. An empty body hashes the empty string (always `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`)

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

Sort whole `key=value` fragments (not by key alone). Do not percent-decode. Keep duplicate keys. This makes the signature independent of parameter order while still preventing any parameter from being tampered with under a captured signature.

Two portability traps, both real:

- **Sort by UTF-8 bytes.** For ASCII/percent-encoded queries — all real traffic — this matches most languages' default string sort. It diverges for raw non-ASCII above U+FFFF, and C#'s default sort is culture-sensitive, which is wrong even for ASCII in some locales. See [`README.md`](./README.md) for the correct comparator per language.
- **Keep trailing empty fragments when splitting.** Ruby's default `split` and Java's one-arg `String.split` drop them; both need an explicit `-1` limit to match the server.

### Sign the exact bytes you send

Serialize the body once, then sign and send **that same byte string**. Do not re-serialize after signing — any difference in key order or whitespace invalidates the signature.

---

## 2. Verifying a webhook

fluxa POSTs an event to your configured callback URL when an order changes state.

| Header | Value |
| --- | --- |
| `X-Fluxa-Event` | Event type; see §3.2 |
| `X-Fluxa-Event-Id` | Same as body `event_id`; use the authenticated body value |
| `X-Fluxa-Timestamp` | Unix seconds |
| `X-Fluxa-Signature` | `hex(HMAC_SHA256(webhook_secret, "<timestamp>.<raw body>"))` |
| `X-Fluxa-Encryption` | present only when payload encryption is on; value `A256GCM` |

To verify:

```
expected = hex(HMAC_SHA256(webhook_secret, X-Fluxa-Timestamp + "." + rawBody))
reject unless constant_time_equals(expected, X-Fluxa-Signature)
```

Rules:

- **Verify against the raw received bytes.** Deserializing and re-serializing changes the bytes and the signature will not match. Frameworks that auto-parse JSON (Express's `express.json()`, and friends) will break this unless you capture the raw body.
- Use a **constant-time** comparison.
- Check `X-Fluxa-Timestamp` freshness (±5 minutes is a reasonable window) to limit replay.
- Delivery is **at-least-once**. Deduplicate by authenticated body `event_id`; see §3.1.
- Failures are retried with exponential backoff (up to 8 attempts). Return `2xx` quickly; anything else counts as a failure.

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
  "event_id": "whk_example_paid",
  "event": "payment.succeeded",
  "order_id": "ord_…",
  "merchant_order_id": "order-1",
  "amount": "9.99",
  "currency": "USD",
  "status": "paid",
  "channel": "mock",
  "channel_name": "Mock (test)",
  "is_test": true
}
```

| Field | Meaning |
| --- | --- |
| `event` | Event type; see §3.2 |
| `event_id` | Opaque event identity; stable across retries, different across events |
| `order_id` | fluxa's order id, `ord_<ULID>` |
| `merchant_order_id` | the idempotency key you supplied at charge time |
| `amount` | the **order total** — not the refunded amount |
| `currency` | currency code |
| `status` | `pending` / `paid` / `failed` / `refunded` / `partially_refunded` / `expired` / `canceled` |
| `channel` | channel code |
| `channel_name` | channel display name |
| `is_test` | **`true` = a test order with no real money — do not ship goods.** Test-key orders do fire webhooks, so you can exercise your integration |
| `refunded_amount` | **cumulative** refunded total; **present only once something has been refunded**. See §3.1 |

Amounts are always **decimal strings**. Never parse them as floats — the server stores `numeric(38,18)` and uses decimal arithmetic. Parsing `9.99` as a double does not visibly corrupt it — but the nearest double is `9.99000000000000021…`, and the error compounds: summing `9.99` a hundred times gives `999.0000000000007`, not `999`. Reconciliation then fails by a cent that no one can find.

### 3.1 Event identity and cumulative refunds

Use the nonempty string `event_id` from the verified, decrypted body as the unique event key. `X-Fluxa-Event-Id` carries the same value for tracing, but headers are not signed; never trust a header-only ID. Retries and manual redeliveries keep the same ID; distinct events have different IDs even when their order, type and amounts match. The demos return 400 for a missing or malformed body ID instead of silently reverting to a lossy composite key. The older `(event, order_id, refunded_amount)` key is not the current contract.

Identity does not establish ordering. For a 1000 order refunded first by 30 and then by 20, the two events carry cumulative `refunded_amount` values `30.00` and `50.00`, and different IDs. Advance the stored total to `max(recorded, refunded_amount)` using decimal arithmetic: adding duplicates refunds; blindly assigning lets a late `30.00` regress `50.00`. Use the positive difference for accounting, not the order's `amount`. Event deduplication and cumulative-state updates belong in the same database transaction.

### 3.2 Current events and ordering

| Event | Handling |
| --- | --- |
| `payment.succeeded` | Fulfill once for an exact-amount order. For `settle_on_received: true`, use cumulative `received_amount` instead of the quoted `amount`. |
| `payment.additional_received` | Additional confirmed funds on an order using settlement by received amount. Atomically advance credited gross to `max(recorded, received_amount)` and apply only the positive difference. Do not add `deposit_amount` separately. This event can arrive before `payment.succeeded`. |
| `payment.failed` | Reconcile the failed order; never regress a newer paid/refunded state because an older delivery arrived late. |
| `payment.refunded` | Advance cumulative `refunded_amount` with decimal max. `reason` distinguishes `refund` from `dispute`. |
| `payment.pending` | Explicit subscription required. Display `payment_method`, `payment_expires_at` and `voucher` only while the order is pending; it is not proof of payment. Later voucher updates have different event IDs. |
| `payment.dispute_created` / `payment.dispute_closed` | Explicit subscription required. Track by `dispute_id`, preserving `is_inquiry`, `escalated`, `outcome` and `corrected`. A closed event may arrive first; a corrected `won` supersedes an earlier `lost`. These events describe disputes, not a balance change; withdrawn funds are reported through `payment.refunded`. |
| `order.created` / `order.expired` / `order.canceled` | Explicit subscription required. Record creation; on closure hide checkout links, embedded forms and deposit instructions. A late creation must not reopen a closed order. |
| `settlement.completed` | Merchant settlement receipt (`settlement_tx`, `settlement_address`, `chain`, `asset`, `fee`); `amount` is the settled net. Do not fulfill or credit the customer again. |
| `subscription.charged` / `subscription.payment_failed` / `subscription.completed` | Subscription lifecycle notifications; do not duplicate fulfillment already performed for the payment event. |

An empty subscription list includes ordinary payment/settlement/subscription events, but excludes the opt-in events above. With a nonempty allow-list, explicitly include every event needed, including `payment.additional_received` when using settlement by received amount. Unknown event types should be logged and acknowledged without fulfillment; non-payment payloads can omit order fields.

Optional payment fields include `paid_at`; `settle_on_received`, `min_received_amount`, `received_amount`; `deposit_id`, `tx_hash`, `deposit_amount` on additional receipts; and `fee`/`net` on settled live payment snapshots. `fee` and `net` are snapshots, not increments; `net` can be negative after a direct-settlement refund. Do not apply max to `fee` or `net`, as refunds can decrease them. Read the current order when reconciling unordered snapshots.

### 3.3 Production processing

The receivers log the business action and use local demo stores (PHP uses file markers); they are not a durable ledger. In production, verify → decrypt → validate `event_id` → begin a database transaction → insert the unique event ID and apply the order transition/cumulative delta → commit → return 2xx. A duplicate committed ID returns 2xx without applying the action again. On failure, roll back both writes and return a failure so the event is retried. For asynchronous work, persist the event durably before acknowledging it. Never claim an event permanently before business changes succeed.

Check `is_test` before any fulfillment or real balance mutation. A successful browser return URL is not payment confirmation: use a verified event or a signed order query. Event IDs are opaque strings, not timestamps or sequence numbers.
