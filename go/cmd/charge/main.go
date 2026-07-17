// Charge demo: create a charge, print the payer instruction, then read the order back.
//
//	go run ./cmd/charge [merchant_order_id]
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"fluxademo/fluxa"
)

func main() {
	cfg, err := fluxa.LoadConfig()
	if err != nil {
		fatal(err)
	}
	if err := cfg.RequireAPIKeys(); err != nil {
		fatal(err)
	}

	merchantOrderID := fmt.Sprintf("demo-%d", time.Now().UnixMilli())
	if len(os.Args) > 1 {
		merchantOrderID = os.Args[1]
	}

	charge := fluxa.ChargeRequest{
		// merchant_order_id is the idempotency key: re-sending the same value returns the
		// same order (idempotent: true) instead of creating a second charge.
		MerchantOrderID:  merchantOrderID,
		Amount:           cfg.Amount, // decimal string — never a float
		Currency:         cfg.Currency,
		Channel:          cfg.Channel,
		Subject:          "fluxa demo item",
		Description:      "Created by fluxa-demo/go",
		Metadata:         map[string]string{"source": "fluxa-demo", "lang": "go"},
		ReturnURL:        "https://example.com/pay/success",
		CancelURL:        "https://example.com/pay/cancel",
		ExpiresInSeconds: 1800,
	}

	ctx := context.Background()
	client := fluxa.NewClient(cfg)

	fmt.Printf("→ POST /api/v1/charges  (merchant_order_id=%s)\n", merchantOrderID)
	res, err := client.CreateCharge(ctx, charge)
	if err != nil {
		fatal(err)
	}

	order, payment, instruction := res.Order, res.Payment, res.Instruction
	fmt.Printf("✓ Order created %s  status=%s  %s %s\n", order.ID, order.Status, order.Amount, order.Currency)
	if res.Idempotent {
		fmt.Println("  (idempotent hit: this merchant_order_id already existed — returning the original order)")
	}
	fmt.Printf("  Channel payment=%s channel=%s\n", payment.ID, payment.ChannelCode)

	// instruction.type decides how to drive the payer.
	switch instruction.Type {
	case "redirect":
		fmt.Printf("\nPayment method: send the payer to the checkout page\n  %s\n", instruction.RedirectURL)
	case "crypto_address":
		fmt.Printf("\nPayment method: transfer to this address\n  Chain: %s  Asset: %s\n  Address: %s\n  Amount due: %s\n  Required confirmations: %d\n",
			instruction.Chain, instruction.Asset, instruction.DepositAddress,
			instruction.AmountDue, instruction.RequiredConfirmations)
	case "client_secret":
		fmt.Printf("\nPayment method: confirm client-side with client_secret\n  %s\n", instruction.ClientSecret)
	case "none":
		fmt.Println("\nThis channel needs no payer action.")
	default:
		fmt.Printf("\nUnknown instruction.type=%s: %+v\n", instruction.Type, instruction)
	}

	fmt.Printf("\n→ GET /api/v1/orders/%s\n", order.ID)
	detail, err := client.GetOrder(ctx, order.ID)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("✓ Read back status=%s\n", detail.Order.Status)
	fmt.Println("\nOnce the order is paid, fluxa POSTs payment.succeeded to the callback URL registered in the portal." +
		"\nTo receive it locally: go run ./cmd/webhook (your callback URL must be publicly reachable — use a tunnel such as ngrok).")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
