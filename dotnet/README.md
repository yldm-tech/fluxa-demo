# fluxa payment integration demo — C# / .NET 8

A merchant integration against the fluxa API with **no third-party NuGet dependencies**:
signing uses `System.Security.Cryptography` (HMACSHA256 / SHA256 / AesGcm), calls go out via
`HttpClient`, JSON is `System.Text.Json`, and the webhook receiver is `System.Net.HttpListener`.
(Only the test project uses xunit.)

The signing contract is [`../spec/SIGNING.md`](../spec/SIGNING.md), pinned by
[`../spec/vectors.json`](../spec/vectors.json) — known-answer vectors generated from fluxa's
actual server-side signing code, which makes them the single criterion for a correct port.

## Layout

| File | Purpose |
| --- | --- |
| `FluxaDemo/Fluxa.cs` | Signing + client + webhook verification/decryption. **This is the file to copy** |
| `FluxaDemo/Config.cs` | Reads the shared `../.env` from the repo root (own parser; no DotNetEnv) |
| `FluxaDemo/Charge.cs` | `charge` entry point: create a charge → print the payer instruction → look the order back up |
| `FluxaDemo/Webhook.cs` | `webhook` entry point: receive and verify callbacks locally |
| `FluxaDemo.Tests/` | Reproduces `vectors.json`, plus the idempotency-key regression tests |

## Prerequisites

The .NET 8 SDK. No install? Every command below has a Docker one-liner.

## Configuration

Every language demo shares the **same** `.env` at the repo root:

```bash
cd ..                  # repo root
cp .env.example .env
$EDITOR .env           # fill in FLUXA_KEY_ID / FLUXA_SECRET / FLUXA_WEBHOOK_SECRET
```

Get those from the merchant portal at **https://pay.fluxa.cash/portal** → Developers →
API Keys → New Key. Choose **Test** mode to start: test orders move no real money but still
fire webhooks, so the whole integration is exercisable safely. The secret is shown once.

Real environment variables take precedence over `.env`, so you can override for a single run:
`FLUXA_CHANNEL=stripe dotnet run --project FluxaDemo -- charge`.

## Running

Run these from this directory (`dotnet/`).

### Known-answer tests (no running server needed)

```bash
dotnet test
# Docker:
docker run --rm -v "$(cd .. && pwd)":/app -w /app/dotnet mcr.microsoft.com/dotnet/sdk:8.0 dotnet test
```

### Create a charge

```bash
dotnet run --project FluxaDemo -- charge [merchant_order_id]
# Docker:
docker run --rm -v "$(cd .. && pwd)":/app -w /app/dotnet mcr.microsoft.com/dotnet/sdk:8.0 \
  dotnet run --project FluxaDemo -- charge
```

Omit `merchant_order_id` and one is generated. It is the idempotency key: re-sending the same
value returns the same order rather than creating a second charge.

### Receive webhooks

```bash
dotnet run --project FluxaDemo -- webhook          # listens on :9000 (change WEBHOOK_PORT)
# Docker (publish the port):
docker run --rm -p 9000:9000 -v "$(cd .. && pwd)":/app -w /app/dotnet mcr.microsoft.com/dotnet/sdk:8.0 \
  dotnet run --project FluxaDemo -- webhook
```

Your receiver must be reachable from the internet, so for local testing expose it with a tunnel
(ngrok, Cloudflare Tunnel) pointed at that port and register the public URL in the portal under
Developers → Webhooks.

A container's `localhost` is the container itself, so point at the hosted API with
`-e FLUXA_BASE_URL=https://pay.fluxa.cash`.

## Integrating into your own project

`FluxaDemo/Fluxa.cs` is standalone — it does not depend on `Config.cs`, so you can copy it in
and keep configuring your app however you already do:

```csharp
var charge = new Dictionary<string, object?>
{
    ["merchant_order_id"] = "your-order-123",  // idempotency key
    ["amount"] = "9.99",                       // decimal string, never a float
    ["currency"] = "USD",
    ["channel"] = "mock",
};

var res = await Fluxa.CreateChargeAsync(cfg, charge);
// Fluxa.Field(res.GetProperty("instruction"), "type") == "redirect"
//   → send the payer to instruction.redirect_url
```

On the webhook side, verify against the **raw received bytes** before parsing anything:

```csharp
// rawBody must be the exact bytes received — read the request stream to the end BEFORE
// parsing. A re-serialized object will not match.
if (!Fluxa.VerifyWebhook(webhookSecret, timestampHeader, rawBody, signatureHeader))
{
    res.StatusCode = 401;
    return;
}
using var doc = JsonDocument.Parse(rawBody);
var evt = doc.RootElement;

// The idempotency key MUST include refunded_amount. (event, order_id) is NOT unique: an order
// can be partially refunded repeatedly, and deduplicating on that pair silently drops the
// second refund while returning 2xx. See ../spec/SIGNING.md §3.1.
var key = $"{Fluxa.Field(evt, "event")}:{Fluxa.Field(evt, "order_id")}:{Fluxa.Field(evt, "refunded_amount")}";
// …process idempotently by key, then return 2xx quickly
```

On a `payment.refunded`, advance your recorded refunded total to
**`max(recorded, refunded_amount)`** — never add, and never assign blindly. Adding
over-refunds on a redelivery; assigning regresses on a reorder, because at-least-once says
nothing about *order*: deliveries are not serialized per order and a failed delivery is retried
after a backoff, so the event carrying `30` can land after the one carrying `50`. A late `30`
is not a duplicate (different key, so it is correctly processed), and assigning would drop your
total from 50 back to 30. Compare with `decimal` and `CultureInfo.InvariantCulture` — not
`double`, and not strings, since `"9.90"` sorts above `"10.00"` ordinally. And check `is_test`
before fulfilling anything.

## The traps worth knowing (.NET-specific)

- **The canonical is 5 lines; with no query the third line is empty, not omitted.** Drop it and
  you have 4 lines, a completely different HMAC, and the server rejects **every** request with
  `401 bad_signature` — not just the ones carrying a query.
- **Sorting must be by UTF-8 byte order.** C#'s default `string.CompareTo` /
  `Array.Sort(string[])` is **culture-sensitive**, which is an outright bug here — wrong even
  for ASCII in some locales. `StringComparer.Ordinal` compares UTF-16 code units and still
  diverges for code points above U+FFFF. This demo compares UTF-8 `byte[]` (see
  `Fluxa.ByteOrder`).
- **Serialize the body once**, and sign and send those same bytes. Note also that
  `JsonSerializer` escapes non-ASCII by default; this demo uses
  `JavaScriptEncoder.UnsafeRelaxedJsonEscaping` to keep its wire bytes in step with the other
  language demos.
- **`AesGcm` wants nonce / ciphertext / tag as three separate spans**, whereas the server sends
  `nonce || ct || tag` as one blob (and Go/Java/Rust pass it through whole). This demo slices
  it: `nonce = blob[..12]`, `tag = blob[^16..]`, `ciphertext = blob[12..^16]`. .NET 8's
  `AesGcm` constructor also requires the tag length explicitly: `new AesGcm(key, 16)`.
- **Use `CryptographicOperations.FixedTimeEquals`** for the signature comparison, never
  `string ==`.
- **Parse decimals with `CultureInfo.InvariantCulture`.** `decimal.Parse` is culture-sensitive:
  in a comma-decimal locale, `"9.90"` parses as `990`.

Amounts are always decimal strings — never `double`/`float`. Doing so does not visibly corrupt
`9.99` (it prints back as `9.99`), but the nearest double is really `9.99000000000000021…`, and
the error compounds: summing `9.99` a hundred times gives `999.0000000000007`, not `999`.
Reconciliation then fails by a cent nobody can find. Keep the string, or use `decimal` if you
must compute.
