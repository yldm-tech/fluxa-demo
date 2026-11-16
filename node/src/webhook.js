// Webhook receiver demo: verify signature → decrypt (if enabled) → process idempotently → 2xx.
//   node src/webhook.js
import { createServer } from "node:http";
import { config } from "./config.js";
import { verifyWebhook, decryptWebhook, dedupeKey } from "./fluxa.js";

// Deduplicate using event_id from the verified, decrypted body; HTTP headers are not signed. Production must commit the event_id unique row and business changes in one transaction before returning 2xx. The local store here only demonstrates duplicate detection.
const processed = new Set();

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
    if (!key) {
      res.writeHead(400).end("missing or invalid event_id");
      return;
    }
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
        if (evt.settle_on_received) {
          console.log("  → Advance credited gross to max(recorded, received_amount) atomically and apply only the positive delta; never add deposit_amount separately or fulfill twice.", evt.received_amount);
          break;
        }
        console.log("  → Ship goods / grant entitlements here (treat amounts as decimal strings, never floats)");
        break;
      case "payment.additional_received":
        if (!evt.is_test) console.log("  → Advance credited gross to max(recorded, received_amount) atomically and apply only the positive delta; never add deposit_amount separately or fulfill twice.", evt.received_amount);
        break;
      case "payment.pending":
        console.log("  → Show the latest voucher/payment_expires_at only while the order is pending; do not fulfill.");
        break;
      case "order.created":
        console.log("  → Record the pending order; do not fulfill.");
        break;
      case "order.expired":
        console.log("  → Close the checkout and hide payment instructions; reconcile current order state before applying late events.");
        break;
      case "order.canceled":
        console.log("  → Close the checkout and hide payment instructions; reconcile current order state before applying late events.");
        break;
      case "payment.dispute_created":
        console.log("  → Track dispute_id and is_inquiry/escalated; a late creation must not overwrite a closed dispute. No balance change here.");
        break;
      case "payment.dispute_closed":
        console.log("  → Track outcome by dispute_id; corrected=true can replace lost with won. No balance change here.");
        break;
      case "settlement.completed":
        console.log("  → Record settlement_tx as a receipt of merchant settlement; do not fulfill or credit the customer again.");
        break;
      case "subscription.charged":
        console.log("  → Record the subscription update; do not duplicate fulfillment from payment.succeeded.");
        break;
      case "subscription.payment_failed":
        console.log("  → Record the failed subscription payment; reconcile subscription state.");
        break;
      case "subscription.completed":
        console.log("  → Record subscription completion; do not fulfill again.");
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
