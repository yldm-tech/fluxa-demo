# Integrating fluxa — contract for AI coding agents

You are writing a merchant integration against the fluxa payment API. This file is the contract.
Follow it exactly and the integration works on the first try. Deviate on any point marked
**MUST** and it fails — usually silently, or with `401 bad_signature`.

This contract is self-sufficient: it has been validated by building a working integration from it
alone, with every vector in §4 passing. Read it start to finish before writing code.

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

**MUST: when there is no query, line 3 is an empty string but THE LINE STILL EXISTS.**
The canonical for a bodyless-query POST is:

```
"POST\n/api/v1/charges\n\n1750000000\n74f74511aebc..."
                       ^^ this empty line
```

Producing a 4-line string here is the single most common integration failure. It yields a
completely different HMAC and the server returns `401 bad_signature` for **every** request, not
just ones with a query.

An empty body hashes the empty string:
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

### 1.1 CANONICAL_QUERY — MUST

Split the raw query on `&`, sort fragments in **UTF-8 byte order**, join with `&`.
Empty query → empty string.

```
""                     → ""
"status=paid&limit=10" → "limit=10&status=paid"
"limit=10&status=paid" → "limit=10&status=paid"
"z=1&z=2&a=3"          → "a=3&z=1&z=2"
```

Sort whole `key=value` fragments, not by key. Do not percent-decode. Keep duplicate keys.

**MUST use a UTF-8 byte comparator.** Language defaults are wrong in ways that pass every ASCII
test and fail in production:

| Language | Wrong (default) | Correct |
| --- | --- | --- |
| JavaScript | `arr.sort()` — UTF-16 | compare `Buffer.from(s,'utf8')` with `Buffer.compare` |
| Java | `String.compareTo` — UTF-16 | `Arrays.compareUnsigned(a.getBytes(UTF_8), b.getBytes(UTF_8))` |
| C# | `Array.Sort(arr)` — **culture-sensitive** | compare UTF-8 `byte[]`; `StringComparer.Ordinal` at minimum |
| Python | — | `key=lambda s: s.encode("utf-8")` |
| PHP | `sort($a)` — `SORT_REGULAR` compares numeric-looking fragments numerically | `sort($a, SORT_STRING)` |
| Ruby | — | `Array#sort` is fine |
| Go, Rust | — | `sort.Strings` / `sort()` are already byte order |

**MUST keep trailing empty fragments when splitting.** Ruby's default `split` and Java's one-arg
`String.split` drop them, diverging from the server. Both need an explicit `-1` limit.

### 1.2 Sign the exact bytes you send — MUST

Serialize the body **once**. Sign that string and send that same string. Do not serialize, sign,
then serialize again — different key order or whitespace produces a different hash and the
signature dies.

```js
const body = JSON.stringify(payload);          // once
const sig  = sign(secret, canonical(..., body));
fetch(url, { body });                          // the same string
```

### 1.3 Amounts — MUST

Amounts are **decimal strings** everywhere, in both directions. The server stores
`numeric(38,18)` and uses decimal arithmetic.

**MUST NOT** parse them into float/double/f64. Parsing `9.99` as a double does not visibly corrupt it — but the nearest double is `9.99000000000000021…`, and the error compounds: summing `9.99` a hundred times gives `999.0000000000007`, not `999`. Reconciliation then fails by a cent that no one can find. Use the string as-is, or a decimal type
(`BigDecimal`, `decimal`, `Decimal`, `rust_decimal`) if you must compute.

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

- `merchant_order_id` is the **idempotency key**. Re-sending the same value returns the same order
  with `"idempotent": true` — it does not create a second charge.
- `channel`'s environment **MUST** match your key's mode, or you get
  `400 channel_environment_mismatch` (this is not a signature error). Test key → test channel
  (e.g. `mock`); live key → live channel. Call the signed `GET /api/v1/channels` to enumerate.

The `201` response is `{order, payment, instruction, idempotent}`. Branch on `instruction.type`:

| `instruction.type` | What to do |
| --- | --- |
| `redirect` | send the payer to `instruction.redirect_url` |
| `crypto_address` | show `deposit_address`, `amount_due`, `chain`, `asset`, `required_confirmations` |
| `client_secret` | confirm client-side with `instruction.client_secret` |
| `none` | nothing — no payer action needed |

Other endpoints: `GET /api/v1/orders/{id}`, `GET /api/v1/orders?status=paid&limit=10`,
`POST /api/v1/orders/{id}/refund`, `GET /api/v1/me`, `GET /api/v1/channels`, `GET /api/v1/wallets`.

---

## 3. Receiving webhooks

```
X-Fluxa-Event:      payment.succeeded | payment.failed | payment.refunded
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

**MUST NOT** verify against a re-serialized object. Frameworks that auto-parse JSON destroy the
raw bytes — capture them first:

```js
// Express: express.raw(), NOT express.json()
app.post("/fluxa/webhook", express.raw({ type: "*/*" }), (req, res) => {
  const raw = req.body.toString("utf8");     // exact received bytes
  ...
});
```

**MUST** use a constant-time comparison (`timingSafeEqual`, `hash_equals`, `compare_digest`,
`hmac.Equal`, `CryptographicOperations.FixedTimeEquals`, `MessageDigest.isEqual`).

Guard the length first. Several of those **throw** rather than return false when the inputs differ
in length — Node's `timingSafeEqual` raises `RangeError: Input buffers must have the same byte
length`, and .NET's `FixedTimeEquals` needs equal spans. A missing or truncated `X-Fluxa-Signature`
is attacker-controlled, so an unguarded compare turns into a 500 instead of a clean 401:

```js
const a = Buffer.from(expected, "utf8");
const b = Buffer.from(provided ?? "", "utf8");
return a.length === b.length && timingSafeEqual(a, b);   // length check FIRST
```

Comparing lengths is not a leak: the expected signature's length is a constant (64 hex chars).

**SHOULD** reject stale timestamps (±300s) after the signature check, to limit replay.

**SHOULD** return `2xx` fast. Non-2xx is retried with exponential backoff, up to 8 attempts.

### 3.1 Idempotency — MUST get this right or you lose money

Delivery is **at-least-once**. The event body:

| Field | Notes |
| --- | --- |
| `event` | `payment.succeeded` / `payment.failed` / `payment.refunded` |
| `order_id` | `ord_<ULID>` |
| `merchant_order_id` | your key from the charge |
| `amount` | **the ORDER TOTAL** — not the refunded amount |
| `currency` | |
| `status` | `paid` / `failed` / `refunded` / `partially_refunded` |
| `channel`, `channel_name` | |
| `is_test` | `true` = test order, **no real money — do not ship goods** |
| `refunded_amount` | **cumulative** refunded total; present only once something was refunded |

**MUST key idempotency on `(event, order_id, refunded_amount)`.**

**MUST NOT** key on `(event, order_id)`. That pair is **not unique**: an order can be partially
refunded repeatedly, and each refund fires its own `payment.refunded`. Deduplicating on the pair
drops the second partial refund as a "duplicate" and returns `2xx` — fluxa records the delivery as
successful and never retries. The customer is under-refunded and **nothing errors anywhere**.

Refund 30 then 20 against a 1000 order:

| Event | `amount` | `refunded_amount` | `status` |
| --- | --- | --- | --- |
| 1st | `1000.00` | `30.00` | `partially_refunded` |
| 2nd | `1000.00` | `50.00` | `partially_refunded` |

`refunded_amount` is cumulative and strictly increasing, so it distinguishes a redelivery (same
value → deduplicate) from a new partial refund (higher value → process).

**MUST advance your recorded total to `max(recorded, refunded_amount)`.** Never add; never assign
blindly:

- **Adding** over-refunds on a redelivery.
- **Assigning** regresses on a reorder. At-least-once says nothing about *order* — the delivery
  queue is claimed concurrently and failures retry after a backoff, so the event carrying `30` can
  land **after** the one carrying `50`. The late `30` is not a duplicate (different key, correctly
  processed), and assigning would drop your total from 50 back to 30.
- **Taking the max** is idempotent *and* order-safe. That is why it is the rule.

Compare as decimals — not floats, and not strings: `"9.90" > "10.00"` is true lexicographically.

**MUST NOT** compute a refund from `amount` — that reads "1 refunded on a 1000 order" as
"1000 refunded".

There is no delivery-id header to key on, so the cumulative-max semantics above are the only
correct approach.

Production: the database unique index goes on `(order_id, event, refunded_amount)`.

**MUST check `is_test` before fulfilling.** Test-key orders fire real webhooks so you can exercise
the integration — shipping goods on one gives product away for a payment that never happened.

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

`spec/vectors.json` holds known-answer vectors generated from fluxa's **actual server-side signing
code**. Your implementation **MUST** reproduce them byte for byte. This is the acceptance test, and
it needs no server and no credentials.

Assert, at minimum:
- every `requests[]` entry: your `canonical` **and** your `signature` match exactly
- every `webhooks[]` entry: your signature matches; and that a tampered body, a wrong secret, and
  an empty signature are all rejected
- every `envelopes[]` entry: decrypts to the expected plaintext
- the no-query canonical is 5 lines with an empty 3rd
- reordering a query does not change the signature, but tampering with a value does
- `get_query_utf16_divergence` — this is the only vector that catches a wrong sort comparator.
  Every other query vector is ASCII, where all comparators agree.

Then check your suite actually has teeth. Run **both** mutations, restoring after each:

1. **Drop the CANONICAL_QUERY line** from your canonical → most request vectors must fail. This
   catches structural breakage, but it is blunt: it reds nearly everything regardless of how good
   your comparator is.
2. **Swap your byte comparator for the language default** (`arr.sort()`, `String.compareTo`,
   `Array.Sort`) → **`get_query_utf16_divergence` must fail, and only it**. This is the sharp one.
   It is the exact failure mode §1.1's table exists to prevent, and the one an ASCII-only suite
   hides — if your suite stays green here, it is not testing the comparator at all.

A suite that survives either mutation is asserting nothing about the signature.

---

## 5. Configuration

All demos read one `.env` at the repo root. Real environment variables take precedence over the
file.

```
FLUXA_BASE_URL=https://pay.fluxa.cash
FLUXA_KEY_ID=pk_test_...
FLUXA_SECRET=sk_test_...          # signs requests; never leaves your server
FLUXA_WEBHOOK_SECRET=whsec_...    # verifies callbacks; a DIFFERENT secret
FLUXA_CHANNEL=mock
```

Keys come from https://pay.fluxa.cash/portal → Developers → API Keys. The secret is shown once.

**MUST NOT** commit `.env`, log the secrets, or send either secret to the browser. The API secret
signs on your server only.

---

## 6. Checklist before you call it done

The whole document matters, but these are the ones that pass every naive test and fail in
production — the rest of your suite will catch the others:

- [ ] Query sorted by **UTF-8 bytes**, not the language default. Every ASCII vector passes either
      way; only `get_query_utf16_divergence` catches it.
- [ ] `split` on `&` keeps trailing empty fragments (Ruby/Java need an explicit `-1`)
- [ ] Idempotency keyed on `(event, order_id, refunded_amount)` — never the pair
- [ ] The refunded total advances to `max(recorded, incoming)` — never added, never assigned
- [ ] `is_test` checked before fulfilling
- [ ] Constant-time compare guarded by a length check first, or an empty signature throws
- [ ] Mutation check: your tests **fail** when you (a) remove the CANONICAL_QUERY line and
      (b) swap the byte comparator for the language default. Green under either means your suite
      is asserting nothing.

---

## 7. Reference implementations

Once your own implementation passes §4, these are worth a read — each is standalone,
dependency-light, and verified against the same vectors:

`node/src/fluxa.js`, `python/src/fluxa.py`, `go/fluxa/fluxa.go`,
`java/src/main/java/cash/fluxa/demo/Fluxa.java`, `php/src/Fluxa.php`, `ruby/lib/fluxa.rb`,
`rust/src/lib.rs`, `dotnet/FluxaDemo/Fluxa.cs`.

Their webhook receivers (`*/webhook.*`) show the idempotency and refund handling from §3.1, and
each language's `test/` directory has a vectors suite you can copy as your starting point.
