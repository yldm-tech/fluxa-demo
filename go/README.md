# fluxa demo — Go

Zero dependencies: only the Go standard library — `go.mod` has no `require` block at all.
Signs merchant API requests, creates charges, and receives verified webhooks.

The signing contract is [`../spec/SIGNING.md`](../spec/SIGNING.md), pinned by
[`../spec/vectors.json`](../spec/vectors.json) — known-answer vectors generated from fluxa's
actual server-side signing code.

## Prerequisites

- **Go 1.21+**, nothing to `go get`
- Config comes from one `.env` in the repo root, **shared by every language demo**:

  ```sh
  cd ..
  cp .env.example .env
  # then fill in FLUXA_KEY_ID / FLUXA_SECRET / FLUXA_WEBHOOK_SECRET
  ```

  Get the keys from the merchant portal at **https://pay.fluxa.cash/portal** → Developers →
  API Keys → New Key. Choose **Test** mode to start: test orders move no real money but still
  fire webhooks, so you can exercise the whole integration safely. The secret is shown once.

  Real environment variables win over `.env`, so `FLUXA_CHANNEL=stripe go run ./cmd/charge`
  overrides it for one run.

## Run

All commands run from this directory (`go/`).

### Create a charge

```sh
go run ./cmd/charge              # merchant_order_id is generated
go run ./cmd/charge my-order-1   # or supply your own (it is the idempotency key)
```

Creates a charge → prints the payer instruction based on `instruction.type` (redirect /
crypto address / client_secret / none) → reads the order back.

### Receive webhooks

```sh
go run ./cmd/webhook             # listens on :9000; change WEBHOOK_PORT in .env
```

Verify → decrypt (if enabled) → deduplicate → 2xx. Your callback URL must be publicly
reachable, so use a tunnel (ngrok, Cloudflare Tunnel) and register that URL in the portal.

### Test

```sh
go test ./...                    # add -v for per-test names
```

Checks byte for byte against `../spec/vectors.json`: every request's canonical string and
signature, every webhook signature (including the tampered-body, wrong-secret and
empty-signature counter-examples), and envelope decryption. No server and no credentials
needed.

### Without Go installed

```sh
docker run --rm -v "$PWD/..":/app -w /app/go golang:1.23 go test ./...
```

Swap `go test ./...` for `go run ./cmd/charge` to charge from the container. Note that
`localhost` inside a container is the container itself — point at the hosted API with
`-e FLUXA_BASE_URL=https://pay.fluxa.cash`.

## Files

| File | Purpose |
| --- | --- |
| `fluxa/fluxa.go` | Signing + HTTP client + webhook verify/decrypt. **This is the file to copy** |
| `fluxa/config.go` | Reads the shared `../.env` (minimal in-tree parser; real env vars win) |
| `fluxa/vectors_test.go` | Checks against `../spec/vectors.json` |
| `cmd/charge/main.go` | Charge entrypoint |
| `cmd/webhook/main.go` | Webhook receiver entrypoint |
| `cmd/webhook/dedupe_test.go` | Pins the refund idempotency key |

`fluxa/fluxa.go` is standalone — copy it (and the `Config` struct it takes) into your own
project.

## Gotchas

The canonical is **5 lines**, and with no query the third line is an **empty line that must
still be there**:

```
METHOD\nPATH\nCANONICAL_QUERY\nTIMESTAMP\nSHA256_HEX(BODY)
```

Drop it and you have a 4-line string whose HMAC is completely different — the server rejects
every request with `401 bad_signature`.

Three more:

- **Serialize the body once.** `Client.Request` calls `json.Marshal` exactly once and both
  hashes and writes those same bytes. Marshaling again after signing can change key order or
  escaping and invalidate the signature.
- **Verify webhooks against the raw bytes.** `io.ReadAll` first, verify, and only then decode
  or decrypt. Compare with `hmac.Equal` (constant time).
- **Amounts are decimal strings, never `float64`.** Parsing `9.99` as a float does not visibly
  corrupt it — but the nearest float64 is `9.99000000000000021…`, and the error compounds:
  summing `9.99` a hundred times gives `999.0000000000007`, not `999`. The server stores
  `numeric(38,18)` and uses decimal arithmetic.

Go needs no special handling for the query sort: `sort.Strings` compares byte-wise, which is
already the UTF-8 byte order the server uses. (This is the trap that bites JavaScript, Java,
and C#, whose default comparators are UTF-16 or culture-sensitive.)

Full details: [`../spec/SIGNING.md`](../spec/SIGNING.md).
