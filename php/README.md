# fluxa payment integration demo — PHP

A dependency-free merchant integration against the fluxa API: HMAC request signing, charges,
order lookup, and webhook verification and decryption.

- **No Composer, no third-party packages.** Only PHP's built-in `hash` / `openssl` / `curl` /
  `json` extensions. `composer.json` declares nothing but the PHP version and those built-in
  extensions — you never need to run `composer install`.
- Targets **PHP 8.1+**.
- The signing contract is [`../spec/SIGNING.md`](../spec/SIGNING.md), pinned by
  [`../spec/vectors.json`](../spec/vectors.json) — known-answer vectors generated from fluxa's
  actual server-side signing code.

| File | Purpose |
| --- | --- |
| `src/Fluxa.php` | Signing / charging / order lookup / webhook verification + decryption. **This is the file to copy** |
| `src/Config.php` | Reads the shared `../.env` from the repo root |
| `src/charge.php` | Charge entry point: create a charge → print the payer instruction → look the order back up |
| `src/webhook.php` | Webhook receiver entry point (runs under PHP's built-in server) |
| `test/vectors_test.php` | Reproduces `../spec/vectors.json`, plus the idempotency-key regression tests (plain assertions, no PHPUnit) |

## Prerequisites

PHP 8.1+. No PHP installed? See the Docker one-liners below.

## Configuration

Every language demo shares the same `.env` at the repo root:

```sh
cd ..            # repo root
cp .env.example .env
$EDITOR .env     # fill in FLUXA_KEY_ID / FLUXA_SECRET / FLUXA_WEBHOOK_SECRET
```

Get those from the merchant portal at **https://pay.fluxa.cash/portal** → Developers →
API Keys → New Key. Choose **Test** mode to start: test orders move no real money but still
fire webhooks, so the whole integration is exercisable safely. The secret is shown once.

Real process environment variables take precedence over `.env`, so you can override for a
single run:

```sh
FLUXA_CHANNEL=stripe php src/charge.php
```

## Running

```sh
cd php

# 1. Known-answer tests (no running server needed — start here)
php test/vectors_test.php

# 2. Create a charge: create → print the payer instruction → look the order back up
php src/charge.php                 # merchant_order_id is generated
php src/charge.php my-order-001    # or supply your own (it is the idempotency key)

# 3. Receive webhooks (the port matches WEBHOOK_PORT in .env, default 9000)
php -S 0.0.0.0:9000 src/webhook.php
```

Your webhook receiver must be reachable from the internet for fluxa to deliver to it, so for
local testing expose it with a tunnel (ngrok, Cloudflare Tunnel) and register that URL in the
portal under Developers → Webhooks.

> How the payer pays depends on `instruction.type` — `redirect` (send them to the checkout
> page) / `crypto_address` (transfer to an address) / `client_secret` (confirm client-side) /
> `none` (nothing to do). `src/charge.php` handles all four.

## No PHP? Use Docker

Run these from the repo root:

```sh
# Known-answer tests
docker run --rm -v "$PWD":/app -w /app/php php:8.3-cli php test/vectors_test.php

# Create a charge
docker run --rm -v "$PWD":/app -w /app/php php:8.3-cli php src/charge.php

# Syntax check
docker run --rm -v "$PWD":/app -w /app/php php:8.3-cli \
  sh -c 'for f in src/*.php test/*.php; do php -l "$f"; done'

# Receive webhooks (publish the container's port 9000)
docker run --rm -p 9000:9000 -v "$PWD":/app -w /app/php php:8.3-cli \
  php -S 0.0.0.0:9000 src/webhook.php
```

A container's `localhost` is the container itself, so point at the hosted API with
`-e FLUXA_BASE_URL=https://pay.fluxa.cash`.

## Integrating into your own project

`src/Fluxa.php` is standalone — it does not depend on `Config.php`, so you can copy it in and
keep configuring your app however you already do:

```php
$fluxa = new Fluxa('https://pay.fluxa.cash', 'pk_test_…', 'sk_test_…');

$res = $fluxa->createCharge([
    'merchant_order_id' => 'your-order-123',  // idempotency key
    'amount' => '9.99',                       // decimal string, never a float
    'currency' => 'USD',
    'channel' => 'mock',
]);
// $res['instruction']['type'] === 'redirect'
//   → send the payer to $res['instruction']['redirect_url']
```

On the webhook side, verify against the **raw received bytes** before parsing anything:

```php
// php://input is the exact bytes received — a re-serialized array will not match.
$rawBody = (string) file_get_contents('php://input');

if (!Fluxa::verifyWebhook(
    $webhookSecret,
    $_SERVER['HTTP_X_FLUXA_TIMESTAMP'] ?? '',
    $rawBody,
    $_SERVER['HTTP_X_FLUXA_SIGNATURE'] ?? '',
)) {
    http_response_code(401);
    return;
}
$evt = json_decode($rawBody, true, 512, JSON_THROW_ON_ERROR);

// The idempotency key MUST include refunded_amount. (event, order_id) is NOT unique: an
// order can be partially refunded repeatedly, and deduplicating on that pair silently drops
// the second refund while returning 2xx. See ../spec/SIGNING.md §3.1.
$key = "{$evt['event']}:{$evt['order_id']}:" . ($evt['refunded_amount'] ?? '');
// …process idempotently by $key, then return 2xx quickly
```

On a `payment.refunded`, advance your recorded refunded total to
**`max(recorded, refunded_amount)`** — never add, and never assign blindly. Adding
over-refunds on a redelivery; assigning regresses on a reorder, because at-least-once says
nothing about *order*: deliveries are not serialized per order and a failed delivery is
retried after a backoff, so the event carrying `30` can land after the one carrying `50`. A
late `30` is not a duplicate (different key, so it is correctly processed), and assigning
would drop your total from 50 back to 30. Compare the values as decimals — not floats, and
not strings, since `"9.90" > "10.00"` in PHP's string comparison. And check `is_test` before
fulfilling anything.

## The traps worth knowing when porting this

- **The canonical is 5 lines, not 4.** With no query, line 3 is an **empty line that must
  still be there**. Drop it and the HMAC is completely different — the server rejects **every**
  request with `401 bad_signature`, not just the ones carrying a query.
- **The bytes you sign must be the bytes you send.** Serialize the body once, sign that exact
  string, and send it; a second `json_encode` after signing can differ in key order or
  escaping and the signature dies. Pass a **string** to cURL's `CURLOPT_POSTFIELDS` — passing
  an array makes cURL switch to multipart encoding and send different bytes.
- **Sort query fragments with `sort($parts, SORT_STRING)`.** It compares raw bytes, matching
  the server. PHP's default `SORT_REGULAR` compares numeric-looking fragments **numerically**
  (`"9"` before `"10"`), which silently diverges.
- **Verify against the raw request body** (`file_get_contents('php://input')`), and compare in
  constant time with `hash_equals`.
- **`openssl_decrypt` takes the tag separately.** The envelope is
  `nonce[12] || ciphertext || tag[16]`, so the tag must be sliced off and passed as `$tag`,
  with the ciphertext no longer carrying it (Go/Java/Rust pass it inline instead). The key is
  `hash('sha256', $secret, true)` — the **raw 32 bytes**, not the 64-character hex string.
- **`hash_hmac()` takes the DATA before the KEY**, the reverse of most crypto APIs. Swapping
  them still returns a plausible-looking hex digest that the server rejects.
- **The `STDOUT` / `STDERR` constants are CLI-only.** `webhook.php` runs under `php -S` (SAPI
  `cli-server`), where `fwrite(STDERR, ...)` is an outright fatal — log via `error_log()`. And
  do not log with `echo`: that writes into the HTTP response body.
- **PHP is shared-nothing.** `php -S` re-executes the script from scratch for every request,
  so an in-process array would always start empty and dedupe **nothing**. This demo uses
  atomic filesystem markers instead (`fopen(..., 'x')` is `O_CREAT|O_EXCL`, a create-if-absent
  that two concurrent deliveries cannot both win). A real project should use a database unique
  constraint — a unique index on `(order_id, event, refunded_amount)`.

  Note the markers live on disk and survive a restart: to replay the same test event, clear
  the marker directory first or you will only ever get `ok (duplicate)`:

  ```sh
  rm -rf "$(php -r 'echo sys_get_temp_dir();')/fluxa-demo-webhook"
  ```

Amounts are always decimal strings (the server stores `numeric(38,18)` and uses decimal
arithmetic). Never convert them to float. Doing so does not visibly corrupt `9.99` — it prints
back as `9.99` — but the nearest double is really `9.99000000000000021…`, and the error
compounds: summing `9.99` a hundred times gives `999.0000000000007`, not `999`. Reconciliation
then fails by a cent nobody can find.
