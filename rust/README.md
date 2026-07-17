# fluxa payment integration demo — Rust

A merchant integration against the fluxa API in Rust: HMAC-signed charges, order lookup, and
webhook receiving with signature verification.

The signing contract is [`../spec/SIGNING.md`](../spec/SIGNING.md), pinned by
[`../spec/vectors.json`](../spec/vectors.json) — known-answer vectors generated from fluxa's
actual server-side signing code.

## Prerequisites

- **Rust 1.85+** (the MSRV comes from ureq 3; every other crate needs less)
- Config comes from `../.env` at the repo root — **every language demo shares that one file**:

  ```sh
  cd ..
  cp .env.example .env
  $EDITOR .env    # fill in FLUXA_KEY_ID / FLUXA_SECRET / FLUXA_WEBHOOK_SECRET
  ```

  Get those from the merchant portal at **https://pay.fluxa.cash/portal** → Developers →
  API Keys → New Key. Choose **Test** mode to start: test orders move no real money but still
  fire webhooks, so the whole integration is exercisable safely. The secret is shown once.

  Real environment variables take precedence over `.env`, so
  `FLUXA_CHANNEL=stripe cargo run --bin charge` overrides it for a single run.

## Running

Run these from this directory (`rust/`).

### Create a charge

```sh
cargo run --bin charge              # merchant_order_id is generated
cargo run --bin charge my-order-1   # or supply your own (it is the idempotency key)
```

Creates a charge → prints the payer instruction based on `instruction.type` (checkout
redirect / deposit address / client_secret / nothing to do) → looks the order back up to
confirm its status.

### Receive webhooks

```sh
cargo run --bin webhook             # listens on :9000; change WEBHOOK_PORT in .env
```

Verify signature → decrypt (if enabled) → deduplicate → return 2xx. Your receiver must be
reachable from the internet, so for local testing expose it with a tunnel (ngrok, Cloudflare
Tunnel) and register that URL in the portal under Developers → Webhooks.

### Test

```sh
cargo test                          # or cargo test -- --nocapture
```

Reproduces `../spec/vectors.json` byte for byte: every request's canonical string and
signature, every webhook signature (including the tampered-body, wrong-secret and
empty-signature counter-cases), and encrypted-envelope decryption. No running server needed.

### Without Rust installed

```sh
docker run --rm -v "$PWD/..:/demo" -w /demo/rust rust:1-slim cargo test
```

Same for charging (swap `cargo test` for `cargo run --bin charge`). A container's
`localhost` is the container itself, so point at the hosted API with
`-e FLUXA_BASE_URL=https://pay.fluxa.cash`.

## Dependencies

Most demos in this repo are dependency-free. Rust cannot be: **the standard library ships
neither crypto nor HTTP**. So the rule here is "every crate replaces one thing the standard
library is missing", and `Cargo.lock` is committed so versions stay pinned.

| crate | Replaces | Why this one |
| --- | --- | --- |
| `hmac` + `sha2` | HMAC-SHA256, SHA-256 | RustCrypto: pure Rust, no C dependencies. `hmac` ships a constant-time `verify_slice`, which saves pulling in `subtle` |
| `aes-gcm` | AES-256-GCM (only needed for encrypted webhooks) | Same family. `getrandom` is off in default features — this demo only decrypts, so it needs no randomness |
| `base64` / `hex` | base64 and hex codecs | De facto standard, no transitive dependencies |
| `serde` + `serde_json` | JSON | De facto standard |
| `ureq` | HTTP client | **Blocking**, so it does not drag in tokio. Its dependency tree is far smaller than `reqwest`'s, which pulls in full tokio + hyper even in `blocking` mode. TLS is its default rustls: pure Rust, no system OpenSSL, and it compiles as-is inside `rust:1-slim` |
| `tiny_http` | HTTP server for the webhook receiver | Also blocking and single-threaded. Hand-rolling a `TcpListener` would save one dependency (the ruby demo does exactly that), but it means parsing Content-Length / chunked yourself — a liability in a demo whose whole point is being copied |

Deliberately absent: **tokio / axum** — this is a demo to read and copy, not a service, and
blocking code is much shorter and clearer. **dotenv** — the `.env` parser is twenty lines in
`src/config.rs`.

## Files

| File | Purpose |
| --- | --- |
| `src/lib.rs` | Signing + HTTP client + webhook verification/decryption. **This is the file to copy** |
| `src/config.rs` | Reads the shared `../.env` (minimal parser; real env vars win) |
| `tests/vectors.rs` | Reproduces `../spec/vectors.json` |
| `tests/dedupe.rs` | Pins the idempotency key against the partial-refund trap |
| `src/bin/charge.rs` | Charge entry point |
| `src/bin/webhook.rs` | Webhook receiver entry point |

## Integrating into your own project

`src/lib.rs` is standalone — it does not depend on `config.rs`, so you can lift it out and
build a `Config` however your app already does configuration:

```rust
use fluxa::{ChargeRequest, Client, Config};

let client = Client::new(cfg);   // cfg: fluxa::Config

let res = client.create_charge(&ChargeRequest {
    merchant_order_id: "your-order-123".to_string(),  // idempotency key
    amount: "9.99".to_string(),                       // decimal string, never a float
    currency: "USD".to_string(),
    channel: "mock".to_string(),
    subject: "T-shirt".to_string(),
    description: String::new(),
    metadata: Default::default(),
    return_url: "https://you.example/success".to_string(),
    cancel_url: "https://you.example/cancel".to_string(),
    expires_in_seconds: 1800,
})?;

// res.instruction.kind == "redirect" → send the payer to res.instruction.redirect_url
```

On the webhook side, verify against the **raw received bytes** before parsing anything:

```rust
use fluxa::{verify_webhook, Event};

// raw_body is the exact bytes received — a re-serialized struct will not match.
if !verify_webhook(&webhook_secret, &timestamp_header, &raw_body, &signature_header) {
    return respond_401();
}
let evt: Event = serde_json::from_slice(&raw_body)?;

// The idempotency key MUST include refunded_amount. (event, order_id) is NOT unique: an
// order can be partially refunded repeatedly, and deduplicating on that pair silently drops
// the second refund while returning 2xx. See ../spec/SIGNING.md §3.1.
let key = evt.dedupe_key();   // event : order_id : refunded_amount
if already_processed(&key) {
    return respond_200();
}
// …process idempotently, then return 2xx quickly
```

On a `payment.refunded`, advance your recorded refunded total to
**`max(recorded, refunded_amount)`** — never add, and never assign blindly. Adding
over-refunds on a redelivery; assigning regresses on a reorder, because at-least-once says
nothing about *order*: deliveries are not serialized per order and a failed delivery is
retried after a backoff, so the event carrying `30` can land after the one carrying `50`. A
late `30` is not a duplicate (different key, so it is correctly processed), and assigning
would drop your total from 50 back to 30. Compare the values as decimals — not floats, and
not strings, since `"9.90" > "10.00"` lexicographically. And check `is_test` before
fulfilling anything.

## The traps worth knowing

The canonical is **5 lines**, and with no query the third line is an **empty line that must
still be there**:

```
METHOD\nPATH\nCANONICAL_QUERY\nTIMESTAMP\nSHA256_HEX(BODY)
```

Drop that line and you have a 4-line string whose HMAC is completely different — the server
then rejects **every** request with `401 bad_signature`, not just the ones carrying a query.

Three more:

- **Serialize the body exactly once.** `Client::create_charge` calls `serde_json::to_string`
  once, and those same bytes are both hashed and written to the wire. That is why it does
  **not** use ureq's `send_json`: that would serialize a second time, and any difference in
  key order or escaping invalidates the signature.
- **Verify webhooks against the raw bytes.** Read the body into a `Vec<u8>` and verify before
  decoding or decrypting anything. `verify_webhook` takes `&[u8]` and feeds it straight to
  the HMAC, so the bytes never round-trip through a `String` where UTF-8 validation or
  replacement characters could alter them. The comparison uses `hmac`'s `verify_slice`, which
  is constant-time and length-safe.
- **AES-GCM tag placement.** The `aes-gcm` crate wants the tag **appended to the
  ciphertext**, which is exactly how the server sends it, so `blob[12..]` goes in whole.
  Node, Ruby, PHP and C# instead take the tag as a separate argument and must slice it off
  the end.

Query sorting needs no special handling here: `sort_unstable()` is already correct. Rust's
`Ord for str` compares bytes, and Rust strings are always UTF-8, so a plain sort **is UTF-8
byte order** and matches the server without a custom comparator. That is Rust-specific luck —
JS and Java default to UTF-16 order, C# to culture-sensitive order, and both have to work
around it. `tests/vectors.rs`'s `query_sorts_by_utf8_byte_order_not_utf16` pins this with
`k=￿&k=😀`.

Amounts are always decimal strings (the server stores `numeric(38,18)` and uses decimal
arithmetic). Never parse them as `f64`. Doing so does not visibly corrupt `9.99` — it prints
back as `9.99` — but the nearest double is really `9.99000000000000021…`, and the error
compounds: summing `9.99` a hundred times gives `999.0000000000007`, not `999`.
Reconciliation then fails by a cent nobody can find. Keep the string, or use a decimal type
(`rust_decimal`) if you must compute.
