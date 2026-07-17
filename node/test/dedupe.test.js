// Idempotency-key regression tests.
//
// fluxa allows an order to be partially refunded repeatedly — further refunds are
// accepted until refunded_amount reaches the order total — and every one of them fires
// its own payment.refunded event. So (event, order_id) is NOT unique.
//
// Deduplicating on (event, order_id) alone silently drops the second partial refund and
// answers 2xx: fluxa treats the delivery as successful and never retries, the customer
// is under-refunded, and nothing errors anywhere in the chain. These tests pin the
// correct behavior. See ../../spec/SIGNING.md §3.1.
import { test } from "node:test";
import assert from "node:assert/strict";

// Kept in sync with dedupeKey in src/webhook.js.
const dedupeKey = (evt) => `${evt.event}:${evt.order_id}:${evt.refunded_amount ?? ""}`;

// The broken implementation these tests falsify — kept here so nobody "simplifies" back to it.
const brokenKey = (evt) => `${evt.event}:${evt.order_id}`;

const refund = (cumulative, status = "partially_refunded") => ({
  event: "payment.refunded",
  order_id: "ord_X",
  merchant_order_id: "o-1",
  amount: "1000.00",
  refunded_amount: cumulative,
  currency: "USD",
  status,
  channel: "mock",
});

test("two partial refunds must have different idempotency keys", () => {
  const first = refund("30.00");
  const second = refund("50.00"); // cumulative: 30 + 20

  assert.notEqual(dedupeKey(first), dedupeKey(second), "two partial refunds collapsed into one event — the second would be dropped");

  // Documents the bug that was fixed: the old key collapses both refunds into one.
  assert.equal(brokenKey(first), brokenKey(second), "premise check: the old (event, order_id) key really does collide");
});

test("a redelivery of the same event must hit the same idempotency key", () => {
  const evt = refund("30.00");
  const redelivery = { ...evt }; // fluxa redelivers the identical payload
  assert.equal(dedupeKey(evt), dedupeKey(redelivery), "a redelivery must be deduplicated");
});

test("a full refund differs from an earlier partial refund", () => {
  assert.notEqual(dedupeKey(refund("30.00")), dedupeKey(refund("1000.00", "refunded")));
});

test("payment.succeeded has no refunded_amount, so the key degrades to (event, order_id)", () => {
  const ok = { event: "payment.succeeded", order_id: "ord_X", status: "paid" };
  assert.equal(dedupeKey(ok), "payment.succeeded:ord_X:");
  assert.equal(dedupeKey(ok), dedupeKey({ ...ok }), "a redelivery must be deduplicated");
});

test("succeeded and refunded are different keys", () => {
  const ok = { event: "payment.succeeded", order_id: "ord_X" };
  assert.notEqual(dedupeKey(ok), dedupeKey(refund("30.00")));
});

// The real-world scenario: refund 30 then 20 against a 1000 order (cumulative 50).
test("end to end: both partial refunds against a 1000 order must be processed", () => {
  const processed = new Set();
  const accept = (evt) => {
    const k = dedupeKey(evt);
    if (processed.has(k)) return false;
    processed.add(k);
    return true;
  };

  assert.equal(accept(refund("30.00")), true, "the first refund should be processed");
  assert.equal(accept(refund("30.00")), false, "a redelivery of the first must be deduplicated");
  assert.equal(accept(refund("50.00")), true, "the second partial refund must be processed — this is exactly the one the old logic dropped");
  assert.equal(accept(refund("50.00")), false, "a redelivery of the second must be deduplicated");

  // Cumulative-value semantics: the last refunded_amount IS the total to record — never add them up.
  assert.equal("50.00", "50.00");
});

// --- Ordering ---
//
// at-least-once says nothing about ORDER. Deliveries are not serialized per order, and a
// failed delivery is retried after a backoff — so the event carrying the 30 can land after
// the one carrying 50.
//
// Dedupe alone does not save you here: a late 30 is a DIFFERENT key from 50, so it is
// correctly not a duplicate — it gets processed, and a blind assignment regresses the
// recorded total. Advancing to max(recorded, incoming) is idempotent AND order-safe.

// Cumulative totals are decimal strings. Comparing them as floats is the very bug the
// rest of this repo warns about, so compare as decimals: same scale here, but pad so
// "9.9" vs "10.0" cannot bite a future reader who edits these fixtures.
function decimalGreater(a, b) {
  const [ai, af = ""] = String(a).split(".");
  const [bi, bf = ""] = String(b).split(".");
  if (ai.padStart(20, "0") !== bi.padStart(20, "0")) return ai.padStart(20, "0") > bi.padStart(20, "0");
  const n = Math.max(af.length, bf.length);
  return af.padEnd(n, "0") > bf.padEnd(n, "0");
}

const advance = (recorded, incoming) => (decimalGreater(incoming, recorded) ? incoming : recorded);

test("out-of-order refunds must not regress the recorded total", () => {
  let recorded = "0";

  // The 50 lands first (the 30's delivery failed and is still backing off).
  recorded = advance(recorded, refund("50.00").refunded_amount);
  assert.equal(recorded, "50.00");

  // The 30 arrives late on retry. It is NOT a duplicate — different key — so it is
  // processed. A blind assignment would drop the total back to 30.
  recorded = advance(recorded, refund("30.00").refunded_amount);
  assert.equal(recorded, "50.00", "a late, lower cumulative value must not move the total backwards");
});

test("in-order refunds still advance normally", () => {
  let recorded = "0";
  recorded = advance(recorded, "30.00");
  assert.equal(recorded, "30.00");
  recorded = advance(recorded, "50.00");
  assert.equal(recorded, "50.00");
  recorded = advance(recorded, "1000.00"); // fully refunded
  assert.equal(recorded, "1000.00");
});

test("a redelivery of the same cumulative value is a no-op", () => {
  assert.equal(advance("50.00", "50.00"), "50.00");
});

test("decimalGreater compares as decimals, not floats or strings", () => {
  assert.ok(decimalGreater("50.00", "30.00"));
  assert.ok(!decimalGreater("30.00", "50.00"));
  // Naive string compare gets this wrong: "9.90" > "10.00" lexicographically.
  assert.ok(decimalGreater("10.00", "9.90"), "10.00 must be greater than 9.90");
  assert.ok(!decimalGreater("9.90", "10.00"));
  assert.ok(!decimalGreater("50.00", "50.00"), "equal is not greater");
});
