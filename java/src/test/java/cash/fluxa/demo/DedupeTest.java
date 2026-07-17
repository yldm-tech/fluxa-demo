// Regression tests for the idempotency key.
//
// fluxa allows an order to be partially refunded more than once — further refunds are
// allowed until refunded_amount reaches the order total — and every refund fires its own
// payment.refunded event. So (event, order_id) is NOT unique.
//
// Deduplicating on just (event, order_id) silently drops the second partial refund and
// returns 2xx, so fluxa records the delivery as successful and never retries. The customer is
// under-refunded and nothing errors anywhere in the chain. These tests pin the correct
// behaviour. See ../spec/SIGNING.md §3.1.
//
//   mvn test
package cash.fluxa.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DedupeTest {

  private static final ObjectMapper JSON = new ObjectMapper();

  /** The tempting-but-wrong key these tests falsify. Kept so nobody "simplifies" back to it. */
  private static String brokenKey(JsonNode evt) {
    return evt.path("event").asText() + ":" + evt.path("order_id").asText();
  }

  /** Builds a partial-refund event. {@code cumulative} is the <b>cumulative</b> refunded total. */
  private static JsonNode refund(String cumulative) {
    return refund(cumulative, "partially_refunded");
  }

  private static JsonNode refund(String cumulative, String status) {
    ObjectNode evt = JSON.createObjectNode();
    evt.put("event", "payment.refunded");
    evt.put("order_id", "ord_X");
    evt.put("merchant_order_id", "o-1");
    evt.put("amount", "1000.00"); // the order total, not this event's refund
    evt.put("refunded_amount", cumulative);
    evt.put("currency", "USD");
    evt.put("status", status);
    evt.put("channel", "mock");
    return evt;
  }

  @Test
  @DisplayName("two partial refunds must have different idempotency keys")
  void twoPartialRefundsGetDifferentKeys() {
    JsonNode first = refund("30.00");
    JsonNode second = refund("50.00"); // cumulative: 30 + 20

    assertNotEquals(
        WebhookDemo.dedupeKey(first),
        WebhookDemo.dedupeKey(second),
        "two partial refunds were judged the same event — the second would be dropped");

    // Pins the trap itself: the naive key really does collide on these two.
    assertEquals(
        brokenKey(first), brokenKey(second), "premise check: the (event, order_id) key does collide here");
  }

  @Test
  @DisplayName("a redelivery of the same event must hit the same idempotency key")
  void redeliveryHitsSameKey() {
    JsonNode evt = refund("30.00");
    JsonNode redelivery = refund("30.00"); // fluxa redelivers the identical payload
    assertEquals(
        WebhookDemo.dedupeKey(evt),
        WebhookDemo.dedupeKey(redelivery),
        "a redelivery must be deduplicated");
  }

  @Test
  @DisplayName("a full refund differs from an earlier partial refund")
  void fullRefundDiffersFromEarlierPartial() {
    assertNotEquals(
        WebhookDemo.dedupeKey(refund("30.00")),
        WebhookDemo.dedupeKey(refund("1000.00", "refunded")));
  }

  @Test
  @DisplayName("payment.succeeded has no refunded_amount, so the key degrades to (event, order_id)")
  void succeededWithoutRefundedAmountDegrades() {
    ObjectNode ok = JSON.createObjectNode();
    ok.put("event", "payment.succeeded");
    ok.put("order_id", "ord_X");
    ok.put("status", "paid");

    // An absent field must not NPE, and must degrade to the old shape (trailing empty part).
    assertEquals("payment.succeeded:ord_X:", WebhookDemo.dedupeKey(ok));
    assertEquals(
        WebhookDemo.dedupeKey(ok),
        WebhookDemo.dedupeKey(ok.deepCopy()),
        "a redelivery must be deduplicated");
  }

  @Test
  @DisplayName("a JSON-null refunded_amount degrades too, rather than becoming the literal \"null\"")
  void explicitNullRefundedAmountDegrades() {
    ObjectNode ok = JSON.createObjectNode();
    ok.put("event", "payment.succeeded");
    ok.put("order_id", "ord_X");
    ok.putNull("refunded_amount");
    assertEquals("payment.succeeded:ord_X:", WebhookDemo.dedupeKey(ok));
  }

  @Test
  @DisplayName("succeeded and refunded are different keys")
  void succeededAndRefundedDiffer() {
    ObjectNode ok = JSON.createObjectNode();
    ok.put("event", "payment.succeeded");
    ok.put("order_id", "ord_X");
    assertNotEquals(WebhookDemo.dedupeKey(ok), WebhookDemo.dedupeKey(refund("30.00")));
  }

  @Test
  @DisplayName("end to end: both partial refunds against a 1000 order must be processed")
  void endToEndBothPartialRefundsProcessed() {
    // The real-world scenario: a 1000 order refunded 30, then 20 (cumulative 50).
    Set<String> processed = new HashSet<>();

    assertTrue(
        processed.add(WebhookDemo.dedupeKey(refund("30.00"))), "the first refund must be processed");
    assertFalse(
        processed.add(WebhookDemo.dedupeKey(refund("30.00"))),
        "a redelivery of the first must be deduplicated");
    assertTrue(
        processed.add(WebhookDemo.dedupeKey(refund("50.00"))),
        "the second partial refund must be processed — this is the one the naive key drops");
    assertFalse(
        processed.add(WebhookDemo.dedupeKey(refund("50.00"))),
        "a redelivery of the second must be deduplicated");

    // Cumulative semantics: the latest refunded_amount IS the total to record — never add
    // the events up. See the ordering tests below for why it is advanced with max().
    assertEquals("50.00", refund("50.00").path("refunded_amount").asText());
  }

  // --- Ordering ---
  //
  // at-least-once says nothing about ORDER. Deliveries are not serialized per order, and a
  // failed delivery is retried after a backoff — so the event carrying the 30 can land after
  // the one carrying 50.
  //
  // Dedupe alone does not save you here: a late 30 is a DIFFERENT key from 50, so it is
  // correctly not a duplicate — it gets processed, and a blind assignment regresses the
  // recorded total. Advancing to max(recorded, incoming) is idempotent AND order-safe.

  /**
   * Moves the recorded total forward only. Cumulative totals are decimal strings: compare
   * them with BigDecimal, never with a double (the bug the rest of this repo warns about) and
   * never as plain strings ("9.90" > "10.00" lexicographically).
   *
   * <p>compareTo, not equals: BigDecimal.equals("50.00") vs ("50.0") is false because equals
   * also compares scale, whereas compareTo compares numeric value.
   */
  private static String advance(String recorded, String incoming) {
    return new BigDecimal(incoming).compareTo(new BigDecimal(recorded)) > 0 ? incoming : recorded;
  }

  @Test
  @DisplayName("out-of-order refunds must not regress the recorded total")
  void outOfOrderRefundsMustNotRegress() {
    String recorded = "0";

    // The 50 lands first (the 30's delivery failed and is still backing off).
    recorded = advance(recorded, refund("50.00").path("refunded_amount").asText());
    assertEquals("50.00", recorded);

    // The 30 arrives late on retry. It is NOT a duplicate — different key — so it is
    // processed. A blind assignment would drop the total back to 30.
    recorded = advance(recorded, refund("30.00").path("refunded_amount").asText());
    assertEquals("50.00", recorded, "a late, lower cumulative value must not move the total backwards");
  }

  @Test
  @DisplayName("in-order refunds still advance normally")
  void inOrderRefundsAdvance() {
    String recorded = "0";
    recorded = advance(recorded, "30.00");
    assertEquals("30.00", recorded);
    recorded = advance(recorded, "50.00");
    assertEquals("50.00", recorded);
    recorded = advance(recorded, "1000.00"); // fully refunded
    assertEquals("1000.00", recorded);
  }

  @Test
  @DisplayName("a redelivery of the same cumulative value is a no-op")
  void redeliveryOfSameCumulativeIsNoop() {
    assertEquals("50.00", advance("50.00", "50.00"));
  }

  @Test
  @DisplayName("advance compares as decimals, not floats or strings")
  void advanceComparesAsDecimals() {
    assertEquals("50.00", advance("30.00", "50.00"));
    assertEquals("50.00", advance("50.00", "30.00"));
    // A naive string compare gets this wrong: "9.90" > "10.00" lexicographically.
    assertEquals("10.00", advance("9.90", "10.00"), "10.00 must be greater than 9.90");
    assertEquals("10.00", advance("10.00", "9.90"), "9.90 must not overwrite 10.00");
  }
}
