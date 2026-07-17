// Regression tests for the idempotency key.
//
// fluxa allows an order to be partially refunded more than once — further refunds are
// allowed until refunded_amount reaches the order total — and every refund fires its own
// payment.refunded event. So (event, order_id) is NOT unique.
//
// Deduplicating on just (event, order_id) silently drops the second partial refund and
// returns 2xx, so fluxa records the delivery as successful and never retries. The customer
// is under-refunded and nothing errors anywhere in the chain. These tests pin the correct
// behaviour. See ../../spec/SIGNING.md §3.1.
//
//   cargo test

use std::collections::HashSet;

use fluxa::Event;

/// Builds an event body. Event's amount / currency / status are required fields, so this
/// uses a struct literal rather than feeding in a minimal JSON blob the way the node demo
/// does.
fn event(name: &str, status: &str, refunded_amount: Option<&str>) -> Event {
    Event {
        event: name.to_string(),
        order_id: "ord_X".to_string(),
        merchant_order_id: "o-1".to_string(),
        amount: "1000.00".to_string(), // the order total, not this event's refund
        currency: "USD".to_string(),
        status: status.to_string(),
        channel: "mock".to_string(),
        paid_at: String::new(),
        refunded_amount: refunded_amount.map(str::to_string),
        is_test: false,
    }
}

/// Builds a partial-refund event. `cumulative` is the **cumulative** refunded total.
fn refund(cumulative: &str) -> Event {
    event("payment.refunded", "partially_refunded", Some(cumulative))
}

/// The tempting-but-wrong key these tests falsify. Kept so that nobody "simplifies" the
/// real key back down to it.
fn broken_key(evt: &Event) -> String {
    format!("{}:{}", evt.event, evt.order_id)
}

#[test]
fn two_partial_refunds_get_different_keys() {
    let first = refund("30.00");
    let second = refund("50.00"); // cumulative: 30 + 20

    assert_ne!(
        first.dedupe_key(),
        second.dedupe_key(),
        "two partial refunds were judged the same event — the second would be dropped"
    );

    // Pins the trap itself: the naive key really does collide on these two.
    assert_eq!(
        broken_key(&first),
        broken_key(&second),
        "premise check: the (event, order_id) key does collide here"
    );
}

#[test]
fn redelivery_of_same_event_hits_same_key() {
    let evt = refund("30.00");
    let redelivery = refund("30.00"); // fluxa redelivers the identical payload
    assert_eq!(
        evt.dedupe_key(),
        redelivery.dedupe_key(),
        "a redelivery must be deduplicated"
    );
}

#[test]
fn full_refund_differs_from_earlier_partial() {
    let partial = refund("30.00");
    let full = event("payment.refunded", "refunded", Some("1000.00"));
    assert_ne!(partial.dedupe_key(), full.dedupe_key());
}

#[test]
fn succeeded_without_refunded_amount_degrades_to_event_and_order_id() {
    let ok = event("payment.succeeded", "paid", None);
    assert_eq!(ok.dedupe_key(), "payment.succeeded:ord_X:");
    assert_eq!(
        ok.dedupe_key(),
        event("payment.succeeded", "paid", None).dedupe_key(),
        "a redelivery must be deduplicated"
    );
}

#[test]
fn succeeded_and_refunded_are_different_keys() {
    let ok = event("payment.succeeded", "paid", None);
    assert_ne!(ok.dedupe_key(), refund("30.00").dedupe_key());
}

/// In the event body, refunded_amount appears only once something has been refunded, and
/// is_test can be absent too — deserialization must not fail on either.
#[test]
fn optional_fields_tolerate_absence() {
    let raw = r#"{"event":"payment.succeeded","order_id":"ord_X","merchant_order_id":"o-1",
                  "amount":"9.99","currency":"USD","status":"paid","channel":"mock"}"#;
    let evt: Event = serde_json::from_str(raw)
        .expect("must parse even when refunded_amount / is_test are absent");
    assert_eq!(evt.refunded_amount, None);
    assert!(!evt.is_test, "is_test must default to false when absent");
    assert_eq!(evt.dedupe_key(), "payment.succeeded:ord_X:");
}

/// The real-world scenario: a 1000 order refunded 30, then 20 (cumulative 50).
#[test]
fn end_to_end_both_partial_refunds_are_processed() {
    let mut processed: HashSet<String> = HashSet::new();
    let mut accept = |evt: &Event| processed.insert(evt.dedupe_key());

    assert!(accept(&refund("30.00")), "the first refund must be processed");
    assert!(
        !accept(&refund("30.00")),
        "a redelivery of the first must be deduplicated"
    );
    assert!(
        accept(&refund("50.00")),
        "the second partial refund must be processed — this is the one the naive key drops"
    );
    assert!(
        !accept(&refund("50.00")),
        "a redelivery of the second must be deduplicated"
    );

    // Cumulative semantics: the latest refunded_amount IS the total to record — never add
    // the events up. See the ordering tests below for why it is advanced with max() rather
    // than assigned.
    assert_eq!(refund("50.00").refunded_amount.as_deref(), Some("50.00"));
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

/// Cumulative totals are decimal strings. Comparing them as floats is the very bug the rest
/// of this repo warns about, and comparing them as plain strings is worse: "9.90" > "10.00"
/// lexicographically. So compare integer and fraction parts separately, zero-padded.
/// A hand-rolled helper rather than a decimal crate — this demo does not need one as a
/// dependency just to compare two totals.
fn decimal_greater(a: &str, b: &str) -> bool {
    let (ai, af) = a.split_once('.').unwrap_or((a, ""));
    let (bi, bf) = b.split_once('.').unwrap_or((b, ""));

    let pad_start = |s: &str| format!("{s:0>20}");
    if pad_start(ai) != pad_start(bi) {
        return pad_start(ai) > pad_start(bi);
    }
    let n = af.len().max(bf.len());
    let pad_end = |s: &str| format!("{s:0<width$}", width = n);
    pad_end(af) > pad_end(bf)
}

/// Move the recorded total forward only.
fn advance(recorded: &str, incoming: &str) -> String {
    if decimal_greater(incoming, recorded) {
        incoming.to_string()
    } else {
        recorded.to_string()
    }
}

#[test]
fn out_of_order_refunds_must_not_regress_the_recorded_total() {
    let mut recorded = "0".to_string();

    // The 50 lands first (the 30's delivery failed and is still backing off).
    recorded = advance(&recorded, refund("50.00").refunded_amount.as_deref().unwrap());
    assert_eq!(recorded, "50.00");

    // The 30 arrives late on retry. It is NOT a duplicate — different key — so it is
    // processed. A blind assignment would drop the total back to 30.
    recorded = advance(&recorded, refund("30.00").refunded_amount.as_deref().unwrap());
    assert_eq!(
        recorded, "50.00",
        "a late, lower cumulative value must not move the total backwards"
    );
}

#[test]
fn in_order_refunds_still_advance_normally() {
    let mut recorded = "0".to_string();
    recorded = advance(&recorded, "30.00");
    assert_eq!(recorded, "30.00");
    recorded = advance(&recorded, "50.00");
    assert_eq!(recorded, "50.00");
    recorded = advance(&recorded, "1000.00"); // fully refunded
    assert_eq!(recorded, "1000.00");
}

#[test]
fn redelivery_of_same_cumulative_value_is_a_noop() {
    assert_eq!(advance("50.00", "50.00"), "50.00");
}

#[test]
fn decimal_greater_compares_as_decimals_not_floats_or_strings() {
    assert!(decimal_greater("50.00", "30.00"));
    assert!(!decimal_greater("30.00", "50.00"));
    // A naive string compare gets this wrong: "9.90" > "10.00" lexicographically.
    assert!(decimal_greater("10.00", "9.90"), "10.00 must be greater than 9.90");
    assert!(!decimal_greater("9.90", "10.00"));
    assert!(!decimal_greater("50.00", "50.00"), "equal is not greater");
}
