// Idempotency-key regression tests.
//
// fluxa allows an order to be partially refunded repeatedly — further refunds are accepted
// until refunded_amount reaches the order total — and every one of them fires its own
// payment.refunded event. So (event, order_id) is NOT unique.
//
// Deduplicating on (event, order_id) alone silently drops the second partial refund and
// answers 2xx: fluxa treats the delivery as successful and never retries, the customer is
// under-refunded, and nothing errors anywhere in the chain. These tests pin the correct
// behavior. See ../../../spec/SIGNING.md §3.1.
//
//	go test ./...
package main

import (
	"encoding/json"
	"strings"
	"testing"

	"fluxademo/fluxa"
)

// The broken implementation these tests falsify — kept here so nobody "simplifies" back to it.
func brokenKey(evt fluxa.Event) string {
	return evt.Event + ":" + evt.OrderID
}

func refund(cumulative, status string) fluxa.Event {
	return fluxa.Event{
		Event:           "payment.refunded",
		OrderID:         "ord_X",
		MerchantOrderID: "o-1",
		Amount:          "1000.00",
		RefundedAmount:  cumulative,
		Currency:        "USD",
		Status:          status,
		Channel:         "mock",
	}
}

func TestTwoPartialRefundsHaveDifferentKeys(t *testing.T) {
	first := refund("30.00", "partially_refunded")
	second := refund("50.00", "partially_refunded") // cumulative: 30 + 20

	if dedupeKey(first) == dedupeKey(second) {
		t.Fatalf("two partial refunds collapsed into one event — the second would be dropped: %s", dedupeKey(first))
	}

	// Documents the bug that was fixed: the old key collapses both refunds into one.
	if brokenKey(first) != brokenKey(second) {
		t.Fatal("premise check failed: the old (event, order_id) key was supposed to collide")
	}
}

func TestRedeliveryHitsSameKey(t *testing.T) {
	evt := refund("30.00", "partially_refunded")
	redelivery := evt // fluxa redelivers the identical payload
	if dedupeKey(evt) != dedupeKey(redelivery) {
		t.Fatal("a redelivery must be deduplicated")
	}
}

func TestFullRefundDiffersFromEarlierPartial(t *testing.T) {
	if dedupeKey(refund("30.00", "partially_refunded")) == dedupeKey(refund("1000.00", "refunded")) {
		t.Fatal("a full refund must have a different key from an earlier partial refund")
	}
}

// payment.succeeded carries no refunded_amount in its JSON, so it unmarshals to the zero
// value (an empty string) and the key degrades to (event, order_id).
func TestSucceededWithoutRefundedAmountDegrades(t *testing.T) {
	const payload = `{"event":"payment.succeeded","order_id":"ord_X","status":"paid"}`

	var evt fluxa.Event
	if err := json.Unmarshal([]byte(payload), &evt); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if evt.RefundedAmount != "" {
		t.Fatalf("with no refund RefundedAmount should be the empty string, got %q", evt.RefundedAmount)
	}
	if got := dedupeKey(evt); got != "payment.succeeded:ord_X:" {
		t.Fatalf("key does not match: got %q", got)
	}

	// fluxa redelivers the identical payload: unmarshaling it again must yield the same key.
	var redelivery fluxa.Event
	if err := json.Unmarshal([]byte(payload), &redelivery); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if dedupeKey(evt) != dedupeKey(redelivery) {
		t.Fatal("a redelivery must be deduplicated")
	}
}

func TestSucceededAndRefundedAreDifferentKeys(t *testing.T) {
	ok := fluxa.Event{Event: "payment.succeeded", OrderID: "ord_X"}
	if dedupeKey(ok) == dedupeKey(refund("30.00", "partially_refunded")) {
		t.Fatal("succeeded and refunded must be different keys")
	}
}

// The real-world scenario: refund 30 then 20 against a 1000 order (cumulative 50).
// This exercises the same dedupe type the handler actually uses, locking included.
func TestEndToEndBothPartialRefundsProcessed(t *testing.T) {
	processed := &dedupe{seen: map[string]struct{}{}}
	accept := func(evt fluxa.Event) bool {
		return processed.markProcessed(dedupeKey(evt))
	}

	cases := []struct {
		evt  fluxa.Event
		want bool
		msg  string
	}{
		{refund("30.00", "partially_refunded"), true, "the first refund should be processed"},
		{refund("30.00", "partially_refunded"), false, "a redelivery of the first must be deduplicated"},
		{refund("50.00", "partially_refunded"), true, "the second partial refund must be processed — this is exactly the one the old logic dropped"},
		{refund("50.00", "partially_refunded"), false, "a redelivery of the second must be deduplicated"},
	}
	for _, c := range cases {
		if got := accept(c.evt); got != c.want {
			t.Errorf("%s: got %v, want %v", c.msg, got, c.want)
		}
	}
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

// Cumulative totals are decimal strings. Comparing them as floats is the very bug the rest
// of this repo warns about, and comparing them as strings is wrong too ("9.90" > "10.00"
// lexicographically). Go has no decimal type in the standard library and this demo takes no
// dependencies, so compare digit by digit: left-pad the integer parts to a common width,
// right-pad the fractions, then a plain string compare is the decimal one.
func decimalGreater(a, b string) bool {
	ai, af := splitDecimal(a)
	bi, bf := splitDecimal(b)

	ai, bi = pad(ai, 20, true), pad(bi, 20, true)
	if ai != bi {
		return ai > bi
	}

	n := len(af)
	if len(bf) > n {
		n = len(bf)
	}
	return pad(af, n, false) > pad(bf, n, false)
}

// splitDecimal splits "10.00" into its integer and fraction parts. A value with no point
// ("0") has an empty fraction.
func splitDecimal(s string) (integer, fraction string) {
	if i := strings.IndexByte(s, '.'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// pad grows s to n characters with zeroes, on the left for integer parts and on the right
// for fractions.
func pad(s string, n int, left bool) string {
	if len(s) >= n {
		return s
	}
	zeroes := strings.Repeat("0", n-len(s))
	if left {
		return zeroes + s
	}
	return s + zeroes
}

// advance moves the recorded total forward only — the max() rule from spec/SIGNING.md §3.1.
func advance(recorded, incoming string) string {
	if decimalGreater(incoming, recorded) {
		return incoming
	}
	return recorded
}

func TestOutOfOrderRefundsDoNotRegressTheTotal(t *testing.T) {
	recorded := "0"

	// The 50 lands first (the 30's delivery failed and is still backing off).
	recorded = advance(recorded, refund("50.00", "partially_refunded").RefundedAmount)
	if recorded != "50.00" {
		t.Fatalf("the first refund to arrive should be recorded: got %q, want %q", recorded, "50.00")
	}

	// The 30 arrives late on retry. It is NOT a duplicate — different key — so it is
	// processed. A blind assignment would drop the total back to 30.
	recorded = advance(recorded, refund("30.00", "partially_refunded").RefundedAmount)
	if recorded != "50.00" {
		t.Fatalf("a late, lower cumulative value must not move the total backwards: got %q, want %q", recorded, "50.00")
	}
}

func TestInOrderRefundsAdvanceNormally(t *testing.T) {
	recorded := "0"
	for _, c := range []struct{ incoming, want string }{
		{"30.00", "30.00"},
		{"50.00", "50.00"},
		{"1000.00", "1000.00"}, // fully refunded
	} {
		if recorded = advance(recorded, c.incoming); recorded != c.want {
			t.Errorf("advancing to %s: got %q, want %q", c.incoming, recorded, c.want)
		}
	}
}

func TestRedeliveryOfTheSameCumulativeValueIsANoop(t *testing.T) {
	if got := advance("50.00", "50.00"); got != "50.00" {
		t.Fatalf("a redelivery must not move the total: got %q, want %q", got, "50.00")
	}
}

func TestDecimalGreaterComparesAsDecimalsNotFloatsOrStrings(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
		msg  string
	}{
		{"50.00", "30.00", true, ""},
		{"30.00", "50.00", false, ""},
		// Naive string compare gets this wrong: "9.90" > "10.00" lexicographically.
		{"10.00", "9.90", true, "10.00 must be greater than 9.90"},
		{"9.90", "10.00", false, "10.00 must be greater than 9.90"},
		{"50.00", "50.00", false, "equal is not greater"},
		// Different scales must still compare arithmetically.
		{"9.9", "10.00", false, "a shorter fraction must not win by length"},
		{"1000.00", "50.00", true, "a wider integer part must win"},
	}
	for _, c := range cases {
		if got := decimalGreater(c.a, c.b); got != c.want {
			t.Errorf("decimalGreater(%q, %q) = %v, want %v: %s", c.a, c.b, got, c.want, c.msg)
		}
	}

	// Premise check: the naive string compare these tests falsify really is wrong.
	if !("9.90" > "10.00") {
		t.Fatal("premise check failed: lexicographically 9.90 was supposed to sort above 10.00")
	}
}
