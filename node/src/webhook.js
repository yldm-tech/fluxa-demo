// Webhook receiver demo: verify signature → decrypt (if enabled) → process idempotently → 2xx.
//   node src/webhook.js
import { createServer } from "node:http";
import { config } from "./config.js";
import { verifyWebhook, decryptWebhook } from "./fluxa.js";

// Delivery is at-least-once: the same event can arrive more than once, so processing
// must be idempotent.
//
// The idempotency key MUST include refunded_amount — (event, order_id) alone is NOT
// unique: a single order can be partially refunded multiple times, and each refund
// fires its own payment.refunded. Deduplicating on just (event, order_id) makes the
// second partial refund look like a duplicate delivery: it gets dropped and answered
// with a 2xx, so fluxa records the delivery as successful and never retries. The
// customer is under-refunded and nothing errors anywhere in the chain.
// refunded_amount is a cumulative total and strictly increasing, so it separates a
// redelivery of the same event (same value → deduplicate) from a genuinely new partial
// refund (higher value → process).
//
// In a real integration this belongs in the database as a unique index on
// (order_id, event, refunded_amount); the in-process Set here is demo-only.
const processed = new Set();

// dedupeKey, per the note above: payment.succeeded / failed carry no refunded_amount,
// so the key degrades to (event, order_id).
const dedupeKey = (evt) => `${evt.event}:${evt.order_id}:${evt.refunded_amount ?? ""}`;

const MAX_SKEW_SECONDS = 300;
const MAX_BODY_BYTES = 1 << 20;

const server = createServer((req, res) => {
  if (req.method !== "POST") {
    res.writeHead(405).end("only POST");
    return;
  }

  // The signature must be verified against the raw bytes: deserializing and
  // re-serializing changes them, and the signature will no longer match.
  const chunks = [];
  let size = 0;
  req.on("data", (c) => {
    size += c.length;
    if (size > MAX_BODY_BYTES) {
      res.writeHead(413).end("body too large");
      req.destroy();
      return;
    }
    chunks.push(c);
  });

  req.on("end", () => {
    if (res.writableEnded) return;
    // Keep the raw bytes for signature verification — hashing the received Buffer directly
    // avoids a String round-trip. The decoded string is only used once the signature passes,
    // for decryption and JSON parsing.
    const rawBytes = Buffer.concat(chunks);
    const rawBody = rawBytes.toString("utf8");
    const event = req.headers["x-fluxa-event"];
    const ts = req.headers["x-fluxa-timestamp"];
    const sig = req.headers["x-fluxa-signature"];
    const encryption = req.headers["x-fluxa-encryption"];

    if (!verifyWebhook(config.webhookSecret, ts, rawBytes, sig)) {
      console.error(`✗ Signature verification failed event=${event} — rejected`);
      res.writeHead(401).end("bad signature");
      return;
    }

    // Check the timestamp only after the signature passes, to limit the replay window.
    const skew = Math.abs(Math.floor(Date.now() / 1000) - Number(ts));
    if (!Number.isFinite(skew) || skew > MAX_SKEW_SECONDS) {
      console.error(`✗ Timestamp outside the allowed window (${skew}s) event=${event} — rejected`);
      res.writeHead(401).end("stale timestamp");
      return;
    }

    // Verify first, then decrypt: the signature covers the envelope as it was sent.
    let payload = rawBody;
    if (encryption === "A256GCM") {
      try {
        payload = decryptWebhook(config.webhookSecret, rawBody);
        console.log("  (payload was an AES-256-GCM encrypted envelope — decrypted)");
      } catch (e) {
        console.error(`✗ Decryption failed: ${e.message}`);
        res.writeHead(400).end("bad envelope");
        return;
      }
    }

    let evt;
    try {
      evt = JSON.parse(payload);
    } catch {
      res.writeHead(400).end("bad json");
      return;
    }

    const key = dedupeKey(evt);
    if (processed.has(key)) {
      // Duplicate delivery: already handled, so return 2xx without shipping or
      // crediting anything a second time.
      console.log(`↺ Duplicate delivery ignored ${key}`);
      res.writeHead(200).end("ok (duplicate)");
      return;
    }
    processed.add(key);

    console.log(`✓ ${evt.event}  order=${evt.order_id}  merchant_order=${evt.merchant_order_id}`);
    console.log(`  ${evt.amount} ${evt.currency}  status=${evt.status}  channel=${evt.channel}`);
    if (evt.is_test) {
      // Orders made with a test key do fire real webhooks (that is how you exercise the
      // integration), but no real money moved.
      console.log("  ⚠ is_test=true: this is a test order — do not ship anything.");
    }

    switch (evt.event) {
      case "payment.succeeded":
        if (evt.is_test) break;
        console.log("  → Ship goods / grant entitlements here (treat amounts as decimal strings, never floats)");
        break;
      case "payment.failed":
        console.log("  → Mark the order failed here");
        break;
      case "payment.refunded":
        // refunded_amount is the CUMULATIVE refunded total, not the amount of this
        // refund; evt.amount is the ORDER TOTAL. Computing a refund from evt.amount
        // would read "1 refunded on a 1000 order" as "1000 refunded".
        //
        // Move your recorded total FORWARD ONLY — never add, and never blindly assign.
        // Delivery is at-least-once and arrival order is not guaranteed, so a retried
        // event carrying 30 can land AFTER the one carrying 50. Assigning would regress
        // your total from 50 back to 30 and under-refund the customer; adding would
        // over-refund on a redelivery. Taking the max is both idempotent (redelivery)
        // and order-safe (reordering). See ../../spec/SIGNING.md §3.1.
        console.log(
          `  → Refunded so far ${evt.refunded_amount ?? "0"} of order total ${evt.amount} ${evt.currency}` +
            ` (status=${evt.status}; partially_refunded means more may follow)`,
        );
        console.log(
          "  → Advance your recorded refunded total to max(recorded, refunded_amount)" +
            " — never assign blindly, and never add",
        );
        break;
    }

    // Return 2xx quickly; anything else is retried by fluxa with exponential backoff
    // (up to 8 attempts).
    res.writeHead(200).end("ok");
  });
});

// Validate the webhook secret at startup rather than failing on the first callback that
// arrives — the config getter exits with an actionable message if it is unset.
void config.webhookSecret;

server.listen(config.webhookPort, () => {
  console.log(`fluxa webhook receiver listening on http://localhost:${config.webhookPort}`);
  console.log("Point your portal callback URL here (it must be publicly reachable — use a tunnel such as ngrok for local testing).");
});
