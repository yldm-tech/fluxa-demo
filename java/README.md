# fluxa payment integration demo — Java 17 (Jackson only)

A merchant integration against the fluxa API using the Java standard library: HMAC-signed
charges, order lookup, and webhook receiving with signature verification.

The only runtime dependency is Jackson, and only for JSON. HTTP uses the built-in
`java.net.http.HttpClient`, signing and decryption use `javax.crypto`, and the webhook
receiver uses the JDK's own `com.sun.net.httpserver.HttpServer`. No Spring, no OkHttp.

The signing contract is [`../spec/SIGNING.md`](../spec/SIGNING.md), pinned by
[`../spec/vectors.json`](../spec/vectors.json) — known-answer vectors generated from fluxa's
actual server-side signing code.

## Prerequisites

- **JDK 17+** and **Maven 3.8+** (no install? see the Docker one-liners below)
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
  `FLUXA_CHANNEL=stripe mvn -q compile exec:java -Dexec.mainClass=cash.fluxa.demo.ChargeDemo`
  overrides it for a single run.

## Running

Run these from this directory (`java/`).

> `exec:java` does not compile on its own, so these commands include `compile` (you can drop
> it once you have run `mvn compile` at least once). Running `mvn exec:java` in a clean
> checkout fails with `ClassNotFoundException`.

### Create a charge

```sh
mvn -q compile exec:java -Dexec.mainClass=cash.fluxa.demo.ChargeDemo
mvn -q compile exec:java -Dexec.mainClass=cash.fluxa.demo.ChargeDemo -Dexec.args="my-order-1"
```

With no argument the `merchant_order_id` is generated; you can also supply your own. It is the
idempotency key, so re-sending the same value returns the same order rather than creating a
second charge.

Creates a charge → prints the payer instruction based on `instruction.type` (checkout redirect
/ deposit address / client_secret / nothing to do) → looks the order back up to confirm its
status.

### Receive webhooks

```sh
mvn -q compile exec:java -Dexec.mainClass=cash.fluxa.demo.WebhookDemo
```

Listens on `:9000` by default (change `WEBHOOK_PORT` in `.env`). Verify signature → decrypt
(if enabled) → deduplicate → return 2xx. Your receiver must be reachable from the internet,
so for local testing expose it with a tunnel (ngrok, Cloudflare Tunnel) and register that URL
in the portal under Developers → Webhooks.

### Test

```sh
mvn test
```

Reproduces `../spec/vectors.json` byte for byte: every request's canonical string and
signature, every webhook signature (including the tampered-body, wrong-secret and
empty-signature counter-cases), and encrypted-envelope decryption. No running server needed.

### Running the built jar directly

```sh
mvn -q package
mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt   # put Jackson on the classpath too
java -cp "target/classes:$(cat target/cp.txt)" cash.fluxa.demo.ChargeDemo
```

### Without a JDK or Maven installed

```sh
docker run --rm -v "$PWD/..:/app" -w /app/java maven:3.9-eclipse-temurin-17 mvn -q test
docker run --rm -v "$PWD/..:/app" -w /app/java maven:3.9-eclipse-temurin-17 \
  mvn -q compile exec:java -Dexec.mainClass=cash.fluxa.demo.ChargeDemo
```

Receiving webhooks needs the port published: `docker run --rm -p 9000:9000 …` (run only one
language's receiver at a time). A container's `localhost` is the container itself, so point at
the hosted API with `-e FLUXA_BASE_URL=https://pay.fluxa.cash`.

## Files

| File | Purpose |
| --- | --- |
| `src/main/java/cash/fluxa/demo/Fluxa.java` | Signing + HTTP client + webhook verification/decryption. **This is the file to copy** |
| `src/main/java/cash/fluxa/demo/Config.java` | Reads the shared `../.env` (minimal parser; real env vars win) |
| `src/main/java/cash/fluxa/demo/ChargeDemo.java` | Charge entry point |
| `src/main/java/cash/fluxa/demo/WebhookDemo.java` | Webhook receiver entry point |
| `src/test/java/cash/fluxa/demo/VectorsTest.java` | Reproduces `../spec/vectors.json` |
| `src/test/java/cash/fluxa/demo/DedupeTest.java` | Pins the idempotency key against the partial-refund trap |

## Integrating into your own project

`Fluxa.java` is standalone — it does not depend on `Config.java`, so you can copy it in and
keep configuring your app however you already do:

```java
Map<String, Object> charge = new LinkedHashMap<>();   // LinkedHashMap: stable key order
charge.put("merchant_order_id", "your-order-123");    // idempotency key
charge.put("amount", "9.99");                         // decimal string, never a float
charge.put("currency", "USD");
charge.put("channel", "mock");

JsonNode res = Fluxa.createCharge(config, charge);
// res.path("instruction").path("type") == "redirect"
//   → send the payer to instruction.redirect_url
```

On the webhook side, verify against the **raw received bytes** before parsing anything:

```java
// rawBody must be the exact bytes received — read the InputStream to the end BEFORE
// parsing. A re-serialized object will not match.
if (!Fluxa.verifyWebhook(webhookSecret, timestampHeader, rawBody, signatureHeader)) {
  respond(exchange, 401, "bad signature");
  return;
}
JsonNode evt = new ObjectMapper().readTree(rawBody);

// The idempotency key MUST include refunded_amount. (event, order_id) is NOT unique: an
// order can be partially refunded repeatedly, and deduplicating on that pair silently drops
// the second refund while returning 2xx. See ../spec/SIGNING.md §3.1.
String key = evt.path("event").asText() + ":"
    + evt.path("order_id").asText() + ":"
    + evt.path("refunded_amount").asText("");
// …process idempotently by key, then return 2xx quickly
```

On a `payment.refunded`, advance your recorded refunded total to
**`max(recorded, refunded_amount)`** — never add, and never assign blindly. Adding
over-refunds on a redelivery; assigning regresses on a reorder, because at-least-once says
nothing about *order*: deliveries are not serialized per order and a failed delivery is
retried after a backoff, so the event carrying `30` can land after the one carrying `50`. A
late `30` is not a duplicate (different key, so it is correctly processed), and assigning
would drop your total from 50 back to 30. Compare with `BigDecimal` — not `double`, and not
strings, since `"9.90".compareTo("10.00") > 0`. And check `is_test` before fulfilling
anything.

## The traps worth knowing

The canonical is **5 lines**, and with no query the third line is an **empty line that must
still be there**:

```
METHOD\nPATH\nCANONICAL_QUERY\nTIMESTAMP\nSHA256_HEX(BODY)
```

Drop that line and you have a 4-line string whose HMAC is completely different — the server
then rejects **every** request with `401 bad_signature`, not just the ones carrying a query.

The Java-specific ones:

- **Do not sort the query with `String.compareTo`.** It compares UTF-16 code units, which
  diverges from the server's UTF-8 byte order for code points above U+FFFF. A UTF-16
  comparator passes every ASCII test and then fails in production. This demo compares UTF-8
  `byte[]` with `Arrays.compareUnsigned`.
- **`String.split` needs an explicit `-1` limit.** The one-arg form drops trailing empty
  fragments, so a query like `a=1&b=` would canonicalize differently from the server.
- **AES-GCM needs the tag length spelled out**: `new GCMParameterSpec(128, nonce)`. The server
  appends the 16-byte tag to the ciphertext, which is exactly the layout `Cipher` expects, so
  `blob[12..]` is passed in whole.
- **Use `MessageDigest.isEqual` for constant-time comparison**, never `String.equals` or
  `Arrays.equals`.
- **Verify webhooks against the raw bytes**: drain the `InputStream` fully, verify, and only
  then deserialize or decrypt.
- **Serialize the body exactly once.** `Fluxa.request` calls `writeValueAsString` once, and
  those same bytes are both hashed and written to the wire. Re-serializing after signing can
  change key order or escaping and the signature dies. Build bodies with `LinkedHashMap` —
  `Map.of` does not preserve order.

Amounts are always decimal strings (the server stores `numeric(38,18)` and uses decimal
arithmetic). Never parse them into `double`/`float`. Doing so does not visibly corrupt `9.99`
— it prints back as `9.99` — but the nearest double is really `9.99000000000000021…`, and the
error compounds: summing `9.99` a hundred times gives `999.0000000000007`, not `999`.
Reconciliation then fails by a cent nobody can find. Keep the string, or use `BigDecimal` if
you must compute.
