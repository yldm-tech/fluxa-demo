// Webhook receiver demo: verify signature -> decrypt (if enabled) -> process idempotently
// -> return 2xx.
//   mvn -q compile exec:java -Dexec.mainClass=cash.fluxa.demo.WebhookDemo
package cash.fluxa.demo;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

public final class WebhookDemo {

  private WebhookDemo() {}

  private static final ObjectMapper JSON = new ObjectMapper();

  // Deduplicate using event_id from the verified, decrypted body; HTTP headers are not signed. Production must commit the event_id unique row and business changes in one transaction before returning 2xx. The local store here only demonstrates duplicate detection.
  private static final Set<String> PROCESSED = ConcurrentHashMap.newKeySet();

  private static final long MAX_SKEW_SECONDS = 300;
  private static final int MAX_BODY_BYTES = 1 << 20;

  // Read only from a verified, decrypted body; empty means invalid.
  static String dedupeKey(JsonNode evt) {
    JsonNode id = evt == null ? null : evt.path("event_id");
    return id != null && id.isTextual() ? id.textValue() : "";
  }

  // Missing values render as empty text; amounts remain decimal strings.
  private static String field(JsonNode evt, String name) {
    JsonNode v = evt.path(name);
    return v.isMissingNode() || v.isNull() ? "" : v.asText();
  }

  public static void main(String[] args) throws IOException {
    Config config = Config.load();
    // Validate at startup rather than failing on the first callback that arrives.
    String webhookSecret = config.webhookSecret();

    HttpServer server = HttpServer.create(new InetSocketAddress(config.webhookPort), 0);
    server.createContext("/", exchange -> handle(exchange, webhookSecret));
    server.setExecutor(Executors.newFixedThreadPool(4));
    server.start();

    System.out.println("fluxa webhook receiver listening on http://localhost:" + config.webhookPort);
    System.out.println(
        "Point your portal callback URL here. It must be reachable from the internet, so for"
            + " local testing expose it with a tunnel such as ngrok and register that URL.");
  }

  private static void handle(HttpExchange exchange, String webhookSecret) throws IOException {
    try (exchange) {
      if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
        respond(exchange, 405, "only POST");
        return;
      }

      // The signature MUST be verified against the raw received bytes: deserializing and
      // re-serializing changes the bytes and the signature will no longer match.
      byte[] raw = readBody(exchange.getRequestBody());
      if (raw == null) {
        respond(exchange, 413, "body too large");
        return;
      }
      // Verify over the raw bytes (below); the decoded string is only used after the signature
      // passes, for decryption and JSON parsing.
      String rawBody = new String(raw, StandardCharsets.UTF_8);

      String event = header(exchange, "X-Fluxa-Event");
      String ts = header(exchange, "X-Fluxa-Timestamp");
      String sig = header(exchange, "X-Fluxa-Signature");
      String encryption = header(exchange, "X-Fluxa-Encryption");

      if (!Fluxa.verifyWebhook(webhookSecret, ts, raw, sig)) {
        System.err.println("✗ Signature verification failed, event=" + event + " — rejected");
        respond(exchange, 401, "bad signature");
        return;
      }

      // Check the timestamp only after the signature passes, to limit the replay window.
      long skew;
      try {
        skew = Math.abs(Instant.now().getEpochSecond() - Long.parseLong(ts));
      } catch (NumberFormatException e) {
        skew = Long.MAX_VALUE;
      }
      if (skew > MAX_SKEW_SECONDS) {
        System.err.println(
            "✗ Timestamp outside the allowed window (" + skew + "s), event=" + event + " — rejected");
        respond(exchange, 401, "stale timestamp");
        return;
      }

      // Verify first, then decrypt: the signature covers the envelope body as it was sent.
      String payload = rawBody;
      if ("A256GCM".equals(encryption)) {
        try {
          payload = Fluxa.decryptWebhook(webhookSecret, rawBody);
          System.out.println("  (payload was an AES-256-GCM encrypted envelope; decrypted)");
        } catch (Exception e) {
          System.err.println("✗ Decryption failed: " + e);
          respond(exchange, 400, "bad envelope");
          return;
        }
      }

      JsonNode evt;
      try {
        evt = JSON.readTree(payload);
      } catch (JacksonException e) {
        respond(exchange, 400, "bad json");
        return;
      }

      String key = dedupeKey(evt);
      if (key.isEmpty()) {
        respond(exchange, 400, "missing or invalid event_id");
        return;
      }
      String name = evt.path("event").asText();
      if (!PROCESSED.add(key)) {
        // Redelivery: already processed, so return 2xx without shipping goods or crediting
        // the account a second time.
        System.out.println("↺ Duplicate delivery ignored " + key);
        respond(exchange, 200, "ok (duplicate)");
        return;
      }

      System.out.println(
          "✓ " + name
              + "  order=" + evt.path("order_id").asText()
              + "  merchant_order=" + evt.path("merchant_order_id").asText());
      System.out.println(
          "  " + evt.path("amount").asText() + " " + evt.path("currency").asText()
              + "  status=" + evt.path("status").asText()
              + "  channel=" + evt.path("channel").asText());

      // MissingNode.asBoolean() returns false for an absent field, so this cannot NPE.
      boolean isTest = evt.path("is_test").asBoolean();
      if (isTest) {
        // Test-key orders fire real webhooks so merchants can exercise the integration, but
        // no real money moved.
        System.out.println("  ⚠ is_test=true: this is a test order — do not actually ship goods.");
      }

      switch (name) {
        case "payment.succeeded" -> {
          if (!isTest && evt.path("settle_on_received").asBoolean()) {
            System.out.println("  → Advance credited gross to max(recorded, received_amount) atomically and apply only the positive delta; never add deposit_amount separately or fulfill twice. " + field(evt, "received_amount"));
          } else if (!isTest) {
            System.out.println(
                "  → Ship goods / grant entitlements here (treat amounts as decimal strings, never floats)");
          }
        }
        case "payment.additional_received" -> {
          if (!isTest) System.out.println("  → Advance credited gross to max(recorded, received_amount) atomically and apply only the positive delta; never add deposit_amount separately or fulfill twice. " + field(evt, "received_amount"));
        }
        case "payment.pending" -> System.out.println("  → Show the latest voucher/payment_expires_at only while the order is pending; do not fulfill.");
        case "order.created" -> System.out.println("  → Record the pending order; do not fulfill.");
        case "order.expired" -> System.out.println("  → Close the checkout and hide payment instructions; reconcile current order state before applying late events.");
        case "order.canceled" -> System.out.println("  → Close the checkout and hide payment instructions; reconcile current order state before applying late events.");
        case "payment.dispute_created" -> System.out.println("  → Track dispute_id and is_inquiry/escalated; a late creation must not overwrite a closed dispute. No balance change here.");
        case "payment.dispute_closed" -> System.out.println("  → Track outcome by dispute_id; corrected=true can replace lost with won. No balance change here.");
        case "settlement.completed" -> System.out.println("  → Record settlement_tx as a receipt of merchant settlement; do not fulfill or credit the customer again.");
        case "subscription.charged" -> System.out.println("  → Record the subscription update; do not duplicate fulfillment from payment.succeeded.");
        case "subscription.payment_failed" -> System.out.println("  → Record the failed subscription payment; reconcile subscription state.");
        case "subscription.completed" -> System.out.println("  → Record subscription completion; do not fulfill again.");
        case "payment.failed" -> System.out.println("  → Mark the order failed here");
        case "payment.refunded" -> {
          // refunded_amount is the CUMULATIVE refunded total, not this event's refund;
          // amount is the ORDER TOTAL — computing a refund from it reads "1 refunded on a
          // 1000 order" as "1000 refunded".
          //
          // Move your recorded total FORWARD ONLY — never add, and never blindly assign.
          // Delivery is at-least-once and arrival order is not guaranteed: deliveries are
          // not serialized per order, and a failed delivery is retried after a backoff, so
          // the event carrying 30 can land AFTER the one carrying 50. Assigning would
          // regress your total from 50 back to 30 and under-refund the customer; adding
          // would over-refund on a redelivery. Taking the max is both idempotent
          // (redelivery) and order-safe (reordering). Compare as decimals (BigDecimal), not
          // floats and not strings. See ../spec/SIGNING.md §3.1.
          String refunded = field(evt, "refunded_amount");
          System.out.println(
              "  → Refunded so far " + (refunded.isEmpty() ? "0" : refunded)
                  + " of order total " + evt.path("amount").asText()
                  + " " + evt.path("currency").asText()
                  + " (status=" + evt.path("status").asText()
                  + "; partially_refunded means more may follow)");
          System.out.println(
              "  → Advance your recorded refunded total to max(recorded, refunded_amount)"
                  + " — never assign blindly, and never add");
        }
        default -> { }
      }

      // Return 2xx quickly; anything else is retried by fluxa with exponential backoff, up
      // to 8 attempts.
      respond(exchange, 200, "ok");
    }
  }

  // readBody drains the whole InputStream before anything parses it — the signature is
  // over these exact bytes. Returns null when the body exceeds MAX_BODY_BYTES.
  private static byte[] readBody(InputStream in) throws IOException {
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    byte[] chunk = new byte[8192];
    int n;
    // -1 is EOF. Looping on `> 0` instead would treat a zero-length read as the end and
    // silently truncate the body — which would then fail signature verification.
    while ((n = in.read(chunk)) != -1) {
      if (buf.size() + n > MAX_BODY_BYTES) return null;
      buf.write(chunk, 0, n);
    }
    return buf.toByteArray();
  }

  private static String header(HttpExchange exchange, String name) {
    String v = exchange.getRequestHeaders().getFirst(name);
    return v == null ? "" : v;
  }

  private static void respond(HttpExchange exchange, int status, String message) throws IOException {
    byte[] body = message.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
    exchange.sendResponseHeaders(status, body.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(body);
    }
  }
}
