# fluxa demo — Ruby

Zero gems: only the standard library (`openssl` / `net/http` / `json` / `socket`). Signs
merchant API requests, creates charges, and receives verified webhooks.

The signing contract is [`../spec/SIGNING.md`](../spec/SIGNING.md), pinned by
[`../spec/vectors.json`](../spec/vectors.json) — known-answer vectors generated from fluxa's
actual server-side signing code.

## Prerequisites

- **Ruby 2.6 – 4.0**. No bundler, no `gem install`.
  (Encrypted webhooks additionally need a Ruby linked against OpenSSL — see
  [below](#encrypted-envelopes-need-an-openssl-linked-ruby).)
- Config comes from one `.env` in the repo root, **shared by every language demo**:

  ```bash
  cd ..
  cp .env.example .env
  $EDITOR .env     # fill in FLUXA_KEY_ID / FLUXA_SECRET / FLUXA_WEBHOOK_SECRET
  ```

  Get the keys from the merchant portal at **https://pay.fluxa.cash/portal** → Developers →
  API Keys → New Key. Choose **Test** mode to start: test orders move no real money but still
  fire webhooks, so you can exercise the whole integration safely. The secret is shown once.

  Real environment variables win over `.env`, so `FLUXA_CHANNEL=stripe ruby lib/charge.rb`
  overrides it for one run.

## Run

All commands run from this directory (`ruby/`).

```bash
ruby test/vectors_test.rb          # check against ../spec/vectors.json (no server, no keys)

ruby lib/charge.rb                 # charge: create → print payer instruction → read back
ruby lib/charge.rb my-order-42     # ...with your own merchant_order_id (the idempotency key)

ruby lib/webhook.rb                # receive webhooks (:9000; change WEBHOOK_PORT in .env)
```

The webhook receiver does verify → decrypt (if enabled) → deduplicate → 2xx. Your callback
URL must be publicly reachable, so use a tunnel and register that URL in the portal:

```bash
ngrok http 9000
```

### Without Ruby installed

```bash
docker run --rm -v "$PWD/..":/app -w /app/ruby ruby:3.3-slim ruby test/vectors_test.rb
```

Swap the command for `ruby lib/charge.rb` to charge from the container. Note that `localhost`
inside a container is the container itself — point at the hosted API with
`-e FLUXA_BASE_URL=https://pay.fluxa.cash`.

## ⚠️ Encrypted envelopes need an OpenSSL-linked Ruby

**This is a LibreSSL limitation, not a Ruby-version one.** macOS ships a system ruby linked
against **LibreSSL**, which cannot do AES-256-GCM *at all* — even encrypting five bytes
raises:

```console
$ ruby -ropenssl -e 'c=OpenSSL::Cipher.new("aes-256-gcm"); c.encrypt; c.key="k"*32; c.iv="n"*12; c.update("hello")+c.final'
-e:1:in `update': OpenSSL::Cipher::CipherError
```

The identical `lib/fluxa.rb` passes **fully** on any OpenSSL-linked Ruby, including a Ruby as
old as 2.6:

| Interpreter | `ruby test/vectors_test.rb` |
| --- | --- |
| macOS system ruby 2.6.10 (**LibreSSL** 3.3.6) | 22 passed, 1 skipped (the envelope — see below) |
| ruby 2.6.10 + **OpenSSL** 1.1.1n (`ruby:2.6-slim`) | 22 passed |
| ruby 3.3.12 + OpenSSL 3.5.6 | 22 passed |
| ruby 4.0.5 + OpenSSL 3.6.2 | 22 passed |

So the fix is an OpenSSL-linked Ruby of **any** version, not a newer one:

```bash
brew install ruby
/opt/homebrew/opt/ruby/bin/ruby lib/webhook.rb
# or: docker run --rm -v "$PWD/..":/app -w /app/ruby -p 9000:9000 ruby:3.3-slim ruby lib/webhook.rb
```

**Everything else works on the system ruby**: request signing, charging, and plaintext webhook
verification all run out of the box. **Only the encrypted envelope** (payload encryption is
off by default) is affected. The test suite probes the interpreter and marks that one case
SKIPPED rather than failing, and `decrypt_webhook` raises `Fluxa::GcmUnavailableError` with
actionable instructions instead of an empty-message `CipherError`. If an encrypted callback
arrives, `webhook.rb` prints that guidance and returns 500 — fluxa retries with exponential
backoff, so you still receive it once you switch interpreters.

## Deliberately avoided dependencies

- **No webrick** — it stopped being a default gem in Ruby 3.0, so the receiver hand-rolls a
  minimal HTTP server on `TCPServer`.
- **No minitest** — it is a bundled gem; the tests use hand-rolled assertions and exit
  non-zero on failure.
- **No `base64`** — not a default gem as of Ruby 3.4; uses `unpack1("m0")` / `pack("m0")`.
- **No `OpenSSL.secure_compare`** — absent from the openssl 2.1 that ships with Ruby 2.6, so
  the constant-time compare is hand-rolled.

## Files

| File | Purpose |
| --- | --- |
| `lib/fluxa.rb` | Signing / charge / order lookup / webhook verify + decrypt. **This is the file to copy** |
| `lib/config.rb` | Reads the shared `../../.env` (real env vars win) |
| `lib/charge.rb` | Charge entrypoint |
| `lib/webhook.rb` | Webhook receiver entrypoint (hand-rolled HTTP on `TCPServer`) |
| `test/vectors_test.rb` | Checks against `../spec/vectors.json`, plus the refund idempotency key |

`lib/fluxa.rb` stands alone and does not depend on `config.rb` — copy it into your own project
and pass it any object responding to `base_url`, `key_id`, and `secret`.

## Gotchas

- **The canonical is 5 lines; with no query the third is an empty line.** Drop it and you have
  4 lines, a completely different HMAC, and `401 bad_signature` on every request.
- **Split the query with `split("&", -1)`.** Ruby's default `split` drops trailing empty
  fragments, which diverges from the server and produces a different HMAC. Sorting needs no
  special care: `String#<=>` already compares bytes, which is the server's UTF-8 byte order.
- **Serialize the body once** — sign and send the same bytes. Re-serializing changes key order
  or spacing and the signature dies instantly.
- **Verify webhooks against the raw bytes.** Deserializing and re-serializing will not match.
  The socket hands you ASCII-8BIT, so the signing input is assembled in binary — otherwise a
  non-ASCII payload raises `Encoding::CompatibilityError`.
- **Amounts are decimal strings, never floats.**

Full details: [`../spec/SIGNING.md`](../spec/SIGNING.md).
