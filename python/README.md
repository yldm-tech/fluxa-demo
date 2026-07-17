# fluxa demo — Python

Zero dependencies: only the Python standard library. Signs merchant API requests, creates
charges, and receives verified webhooks.

The signing contract is [`../spec/SIGNING.md`](../spec/SIGNING.md), pinned by
[`../spec/vectors.json`](../spec/vectors.json) — known-answer vectors generated from fluxa's
actual server-side signing code.

## Prerequisites

- **Python 3.9+**, no `pip install` needed (the one exception is
  [encrypted webhooks](#encrypted-webhooks-the-cryptography-dependency) below)
- Config comes from one `.env` in the repo root, **shared by every language demo**:

  ```sh
  cd ..
  cp .env.example .env
  # then fill in FLUXA_KEY_ID / FLUXA_SECRET / FLUXA_WEBHOOK_SECRET
  ```

  Get the keys from the merchant portal at **https://pay.fluxa.cash/portal** → Developers →
  API Keys → New Key. Choose **Test** mode to start: test orders move no real money but still
  fire webhooks, so you can exercise the whole integration safely. The secret is shown once.

  Real environment variables win over `.env`, so `FLUXA_CHANNEL=stripe python3 src/charge.py`
  overrides it for one run.

## Run

All commands run from this directory (`python/`).

### Create a charge

```sh
python3 src/charge.py              # merchant_order_id is generated
python3 src/charge.py my-order-1   # or supply your own (it is the idempotency key)
```

Creates a charge → prints the payer instruction based on `instruction.type` (redirect /
crypto address / client_secret / none) → reads the order back.

### Receive webhooks

```sh
python3 src/webhook.py             # listens on :9000; change WEBHOOK_PORT in .env
```

Verify → decrypt (if enabled) → deduplicate → 2xx. Your callback URL must be publicly
reachable, so use a tunnel (ngrok, Cloudflare Tunnel) and register that URL in the portal.

### Test

```sh
python3 -m unittest discover -s test      # add -v for per-test names
```

Checks byte for byte against `../spec/vectors.json`: every request's canonical string and
signature, every webhook signature (including the tampered-body, wrong-secret and
empty-signature counter-examples), and envelope decryption. No server and no credentials
needed.

> Do not delete `test/__init__.py` — without it `unittest discover` finds no tests at all and
> still prints `OK` ("Ran 0 tests"), a green result that tested nothing.

### Without Python installed

```sh
docker run --rm -v "$PWD/..":/app -w /app/python python:3.12-slim python -m unittest discover -s test
```

Swap the command for `python src/charge.py` to charge from the container. Note that
`localhost` inside a container is the container itself — point at the hosted API with
`-e FLUXA_BASE_URL=https://pay.fluxa.cash`.

## Encrypted webhooks (the `cryptography` dependency)

Signing, charging, order lookup, and plaintext webhook verification are **all
zero-dependency** — standard library only.

There is exactly one exception. When payload encryption is enabled, the callback body is an
AES-256-GCM envelope. The Python standard library has no AES, and hand-rolling one would be
malpractice, so that single path needs:

```sh
pip install cryptography
```

**Payload encryption is off by default**, so you need nothing installed unless you turn it on.
Without it installed:

- signing / verification / charging / order lookup all work normally
- if an encrypted callback does arrive, `decrypt_webhook()` raises an error that tells you to
  `pip install cryptography`
- the envelope case in the vectors test **skips** (it does not fail); install the package and
  it runs and passes

## Files

| File | Purpose |
| --- | --- |
| `src/fluxa.py` | Signing + HTTP client + webhook verify/decrypt. **This is the file to copy** |
| `src/config.py` | Reads the shared `../.env` (real env vars win) |
| `src/charge.py` | Charge entrypoint |
| `src/webhook.py` | Webhook receiver entrypoint |
| `test/test_vectors.py` | Checks against `../spec/vectors.json` |
| `test/test_dedupe.py` | Pins the refund idempotency key |

`src/fluxa.py` stands alone and does not depend on `config.py` — copy it into your own
project and pass it any object with `base_url`, `key_id`, and `secret` attributes.

## Gotchas

The canonical is **5 lines**, and with no query the third line is an **empty line that must
still be there**:

```
METHOD\nPATH\nCANONICAL_QUERY\nTIMESTAMP\nSHA256_HEX(BODY)
```

Drop it and you have a 4-line string whose HMAC is completely different — the server rejects
every request with `401 bad_signature`.

Two more:

- **Serialize the body once.** Sign and send that exact byte string; re-serializing after
  signing changes key order or spacing and the signature dies.
- **Amounts are decimal strings, never floats.** Parsing `9.99` as a float does not visibly
  corrupt it — but the nearest double is `9.99000000000000021…`, and the error compounds:
  summing `9.99` a hundred times gives `999.0000000000007`, not `999`. The server stores
  `numeric(38,18)` and uses decimal arithmetic. Use `Decimal` if you must compute.

Full details: [`../spec/SIGNING.md`](../spec/SIGNING.md).
