use fluxa::{ChargeRequest, ChargeResponse, Event};
use serde_json::json;

#[test]
fn optional_charge_fields_preserve_omission_and_explicit_false() {
    let mut charge = ChargeRequest {
        merchant_order_id: "order-fixture".into(),
        amount: "10.00".into(),
        currency: "USD".into(),
        ..Default::default()
    };
    let value = serde_json::to_value(&charge).unwrap();
    for field in [
        "channel",
        "network",
        "method",
        "presentation",
        "settle_on_received",
        "min_received_amount",
    ] {
        assert!(
            value.get(field).is_none(),
            "unset option {field} must be omitted"
        );
    }
    charge.settle_on_received = Some(false);
    charge.min_received_amount = Some("5.00".into());
    charge.network = "tron".into();
    charge
        .metadata
        .insert("nested".into(), json!({"enabled": true}));
    let value = serde_json::to_value(&charge).unwrap();
    assert_eq!(value["settle_on_received"], false);
    assert_eq!(value["min_received_amount"], "5.00");
    assert_eq!(value["network"], "tron");
    assert_eq!(value["metadata"]["nested"]["enabled"], true);
}

#[test]
fn current_response_fields_preserve_decimal_strings() {
    let charge: ChargeResponse = serde_json::from_value(json!({
        "order": {"id":"ord_1","amount":"10","currency":"USD","status":"pending"},
        "payment":{"id":"pay_1","channel_code":"stripe"},
        "instruction":{"type":"client_secret","client_secret":"fixture_secret","publishable_key":"fixture_public","expires_at":"2026-11-16T00:00:00Z"}
    })).unwrap();
    assert_eq!(charge.instruction.publishable_key, "fixture_public");
    assert!(charge.instruction.expires_at.is_some());
    let event: Event = serde_json::from_value(json!({
        "event_id":"whk_fixture","event":"payment.additional_received","settle_on_received":true,
        "received_amount":"110.000000000000000001","fee":"1.1","net":"108.900000000000000001","deposit_id":"dep_1"
    })).unwrap();
    assert!(event.settle_on_received);
    assert_eq!(event.received_amount, "110.000000000000000001");
    assert_eq!(event.net.as_deref(), Some("108.900000000000000001"));
    assert_eq!(event.deposit_id.as_deref(), Some("dep_1"));
}
