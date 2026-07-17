# Idempotency-key regression tests.
#
# fluxa allows an order to be partially refunded repeatedly — further refunds are accepted
# until refunded_amount reaches the order total — and every one of them fires its own
# payment.refunded event. So (event, order_id) is NOT unique.
#
# Deduplicating on (event, order_id) alone silently drops the second partial refund and
# answers 2xx: fluxa treats the delivery as successful and never retries, the customer is
# under-refunded, and nothing errors anywhere in the chain. These tests pin the correct
# behavior. See ../../spec/SIGNING.md §3.1.
#
#   python3 -m unittest discover -s test
import unittest
from decimal import Decimal


# Kept in sync with dedupe_key in src/webhook.py. Redefined here rather than imported:
# src/webhook.py imports config, which sys.exits when there is no .env — and these tests
# must run fully offline, with no credentials.
def dedupe_key(evt):
    refunded = evt.get("refunded_amount")
    return "{}:{}:{}".format(
        evt.get("event"), evt.get("order_id"), "" if refunded is None else refunded
    )


# The broken implementation these tests falsify — kept here so nobody "simplifies" back to it.
def broken_key(evt):
    return "{}:{}".format(evt.get("event"), evt.get("order_id"))


def refund(cumulative, status="partially_refunded"):
    return {
        "event": "payment.refunded",
        "order_id": "ord_X",
        "merchant_order_id": "o-1",
        "amount": "1000.00",
        "refunded_amount": cumulative,
        "currency": "USD",
        "status": status,
        "channel": "mock",
    }


class DedupeKey(unittest.TestCase):
    def test_two_partial_refunds_differ(self):
        """Two partial refunds must have different idempotency keys."""
        first = refund("30.00")
        second = refund("50.00")  # cumulative: 30 + 20

        self.assertNotEqual(
            dedupe_key(first), dedupe_key(second), "two partial refunds collapsed into one event — the second would be dropped"
        )

        # Documents the bug that was fixed: the old key collapses both refunds into one.
        self.assertEqual(
            broken_key(first), broken_key(second), "premise check: the old (event, order_id) key really does collide"
        )

    def test_redelivery_hits_same_key(self):
        """A redelivery of the same event must hit the same idempotency key."""
        evt = refund("30.00")
        redelivery = dict(evt)  # fluxa redelivers the identical payload
        self.assertEqual(dedupe_key(evt), dedupe_key(redelivery), "a redelivery must be deduplicated")

    def test_full_refund_differs_from_earlier_partial(self):
        """A full refund differs from an earlier partial refund."""
        self.assertNotEqual(dedupe_key(refund("30.00")), dedupe_key(refund("1000.00", "refunded")))

    def test_succeeded_without_refunded_amount_degrades(self):
        """payment.succeeded has no refunded_amount, so the key degrades to (event, order_id)."""
        ok = {"event": "payment.succeeded", "order_id": "ord_X", "status": "paid"}
        self.assertEqual(dedupe_key(ok), "payment.succeeded:ord_X:")
        self.assertEqual(dedupe_key(ok), dedupe_key(dict(ok)), "a redelivery must be deduplicated")

    def test_succeeded_and_refunded_are_different_keys(self):
        """succeeded and refunded are different keys."""
        ok = {"event": "payment.succeeded", "order_id": "ord_X"}
        self.assertNotEqual(dedupe_key(ok), dedupe_key(refund("30.00")))


class DedupeEndToEnd(unittest.TestCase):
    def test_both_partial_refunds_are_processed(self):
        """End to end: both partial refunds against a 1000 order must be processed."""
        processed = set()

        def accept(evt):
            k = dedupe_key(evt)
            if k in processed:
                return False
            processed.add(k)
            return True

        self.assertTrue(accept(refund("30.00")), "the first refund should be processed")
        self.assertFalse(accept(refund("30.00")), "a redelivery of the first must be deduplicated")
        self.assertTrue(accept(refund("50.00")), "the second partial refund must be processed — this is exactly the one the old logic dropped")
        self.assertFalse(accept(refund("50.00")), "a redelivery of the second must be deduplicated")


# --- Ordering ---
#
# at-least-once says nothing about ORDER. Deliveries are not serialized per order, and a
# failed delivery is retried after a backoff — so the event carrying the 30 can land after
# the one carrying 50.
#
# Dedupe alone does not save you here: a late 30 is a DIFFERENT key from 50, so it is
# correctly not a duplicate — it gets processed, and a blind assignment regresses the
# recorded total. Advancing to max(recorded, incoming) is idempotent AND order-safe.


# Cumulative totals are decimal strings. Comparing them as floats is the very bug the rest
# of this repo warns about, and comparing them as strings is wrong too, so parse them with
# decimal.Decimal — exact, and in the standard library. The recorded value stays a string:
# Decimal is for the comparison only.
def advance(recorded, incoming):
    return incoming if Decimal(incoming) > Decimal(recorded) else recorded


class RefundOrdering(unittest.TestCase):
    def test_out_of_order_refunds_do_not_regress_the_total(self):
        """Out-of-order refunds must not regress the recorded total."""
        recorded = "0"

        # The 50 lands first (the 30's delivery failed and is still backing off).
        recorded = advance(recorded, refund("50.00")["refunded_amount"])
        self.assertEqual(recorded, "50.00")

        # The 30 arrives late on retry. It is NOT a duplicate — different key — so it is
        # processed. A blind assignment would drop the total back to 30.
        recorded = advance(recorded, refund("30.00")["refunded_amount"])
        self.assertEqual(recorded, "50.00", "a late, lower cumulative value must not move the total backwards")

    def test_in_order_refunds_advance_normally(self):
        """In-order refunds still advance normally."""
        recorded = "0"
        recorded = advance(recorded, "30.00")
        self.assertEqual(recorded, "30.00")
        recorded = advance(recorded, "50.00")
        self.assertEqual(recorded, "50.00")
        recorded = advance(recorded, "1000.00")  # fully refunded
        self.assertEqual(recorded, "1000.00")

    def test_redelivery_of_the_same_cumulative_value_is_a_noop(self):
        """A redelivery of the same cumulative value is a no-op."""
        self.assertEqual(advance("50.00", "50.00"), "50.00")

    def test_comparison_is_decimal_not_float_or_string(self):
        """The comparison is a decimal one, not a float or string one."""
        self.assertEqual(advance("30.00", "50.00"), "50.00")
        self.assertEqual(advance("50.00", "30.00"), "50.00")

        # Naive string compare gets this wrong: "9.90" > "10.00" lexicographically.
        self.assertEqual(advance("9.90", "10.00"), "10.00", "10.00 must be greater than 9.90")
        self.assertEqual(advance("10.00", "9.90"), "10.00", "10.00 must be greater than 9.90")

        # Premise check: the naive string compare this test falsifies really is wrong.
        self.assertGreater("9.90", "10.00", "premise check: lexicographically 9.90 really does sort above 10.00")
        self.assertGreater(Decimal("10.00"), Decimal("9.90"), "as decimals the order is the arithmetic one")


if __name__ == "__main__":
    unittest.main()
