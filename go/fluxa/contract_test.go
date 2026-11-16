package fluxa

import (
	"encoding/json"
	"testing"
)

func TestChargeOptionalFieldsPreserveOmissionAndExplicitFalse(t *testing.T) {
	charge := ChargeRequest{MerchantOrderID: "order-fixture", Amount: "10.00", Currency: "USD"}
	decode := func() map[string]any {
		raw, err := json.Marshal(charge)
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	for _, field := range []string{"channel", "network", "method", "presentation", "settle_on_received", "min_received_amount"} {
		if _, exists := decode()[field]; exists {
			t.Fatalf("unset option %s must be omitted", field)
		}
	}
	settle := false
	minimum := "5.00"
	charge.SettleOnReceived = &settle
	charge.MinReceivedAmount = &minimum
	charge.Network = "tron"
	charge.Metadata = map[string]any{"customer": "customer-fixture", "nested": map[string]any{"enabled": true}}
	result := decode()
	if value, exists := result["settle_on_received"]; !exists || value != false {
		t.Fatal("explicit false lost", result)
	}
	if result["min_received_amount"] != minimum || result["network"] != "tron" {
		t.Fatal("optional fields lost", result)
	}
	if result["metadata"].(map[string]any)["nested"].(map[string]any)["enabled"] != true {
		t.Fatal("metadata must preserve arbitrary JSON")
	}
}

func TestCurrentResponseFields(t *testing.T) {
	var charge ChargeResponse
	if err := json.Unmarshal([]byte(`{"order":{"id":"ord_1","amount":"10","currency":"USD","status":"pending","settle_on_received":false},"payment":{"id":"pay_1"},"instruction":{"type":"client_secret","client_secret":"fixture_secret","publishable_key":"fixture_public","expires_at":"2026-11-16T00:00:00Z"}}`), &charge); err != nil {
		t.Fatal(err)
	}
	if charge.Instruction.PublishableKey != "fixture_public" || charge.Instruction.ExpiresAt == nil {
		t.Fatal("embedded instruction fields lost", charge.Instruction)
	}
	var event Event
	if err := json.Unmarshal([]byte(`{"event_id":"whk_fixture","event":"payment.additional_received","settle_on_received":true,"received_amount":"110.000000000000000001","fee":"1.1","net":"108.900000000000000001","deposit_id":"dep_1","deposit_amount":"10.000000000000000001"}`), &event); err != nil {
		t.Fatal(err)
	}
	if !event.SettleOnReceived || event.ReceivedAmount != "110.000000000000000001" || event.Net != "108.900000000000000001" || event.DepositID != "dep_1" {
		t.Fatal("receipt fields must preserve exact strings", event)
	}
}
