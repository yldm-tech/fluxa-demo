// Webhook receiver demo: verify signature -> decrypt (if enabled) -> process idempotently -> 2xx.
//
//	go run ./cmd/webhook
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"fluxademo/fluxa"
)

const (
	maxSkewSeconds = 300
	maxBodyBytes   = 1 << 20
)

// Delivery is at-least-once: the same event can arrive more than once, so processing must
// be idempotent.
//
// The idempotency key MUST include refunded_amount — (event, order_id) alone is NOT unique:
// a single order can be partially refunded multiple times, and each refund fires its own
// payment.refunded. Deduplicating on just (event, order_id) makes the second partial refund
// look like a duplicate delivery: it gets dropped and answered with a 2xx, so fluxa records
// the delivery as successful and never retries. The customer is under-refunded and nothing
// errors anywhere in the chain.
// refunded_amount is a cumulative total and strictly increasing, so it separates a
// redelivery of the same event (same value -> deduplicate) from a genuinely new partial
// refund (higher value -> process).
//
// In a real integration this belongs in the database as a unique index on
// (order_id, event, refunded_amount); the in-process map here is demo-only.
type dedupe struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

// dedupeKey, per the note above: payment.succeeded / failed carry no refunded_amount, so
// the field is the zero value (an empty string) and the key degrades to (event, order_id).
func dedupeKey(evt fluxa.Event) string {
	return evt.Event + ":" + evt.OrderID + ":" + evt.RefundedAmount
}

// markProcessed records the key and returns true if this is the first time it is seen.
// net/http serves requests concurrently, so the lock is required.
func (d *dedupe) markProcessed(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[key]; ok {
		return false
	}
	d.seen[key] = struct{}{}
	return true
}

type handler struct {
	secret    string
	processed *dedupe
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST", http.StatusMethodNotAllowed)
		return
	}

	// The signature must be verified against the raw bytes: deserializing and re-serializing
	// changes them, and the signature will no longer match. So io.ReadAll first, and do all
	// decoding only after verification.
	rawBody, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}

	event := r.Header.Get("X-Fluxa-Event")
	ts := r.Header.Get("X-Fluxa-Timestamp")
	sig := r.Header.Get("X-Fluxa-Signature")
	encryption := r.Header.Get("X-Fluxa-Encryption")

	if !fluxa.VerifyWebhook(h.secret, ts, rawBody, sig) {
		fmt.Fprintf(os.Stderr, "✗ Signature verification failed event=%s — rejected\n", event)
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}

	// Check the timestamp only after the signature passes, to limit the replay window.
	tsSeconds, err := strconv.ParseInt(ts, 10, 64)
	skew := time.Now().Unix() - tsSeconds
	if skew < 0 {
		skew = -skew
	}
	if err != nil || skew > maxSkewSeconds {
		fmt.Fprintf(os.Stderr, "✗ Timestamp outside the allowed window (%ds) event=%s — rejected\n", skew, event)
		http.Error(w, "stale timestamp", http.StatusUnauthorized)
		return
	}

	// Verify first, then decrypt: the signature covers the envelope as it was sent.
	payload := rawBody
	if encryption == "A256GCM" {
		payload, err = fluxa.DecryptWebhook(h.secret, rawBody)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ Decryption failed: %v\n", err)
			http.Error(w, "bad envelope", http.StatusBadRequest)
			return
		}
		fmt.Println("  (payload was an AES-256-GCM encrypted envelope — decrypted)")
	}

	var evt fluxa.Event
	if err := json.Unmarshal(payload, &evt); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	key := dedupeKey(evt)
	if !h.processed.markProcessed(key) {
		// Duplicate delivery: already handled, so return 2xx without shipping or crediting
		// anything a second time.
		fmt.Printf("↺ Duplicate delivery ignored %s\n", key)
		writeOK(w, "ok (duplicate)")
		return
	}

	fmt.Printf("✓ %s  order=%s  merchant_order=%s\n", evt.Event, evt.OrderID, evt.MerchantOrderID)
	fmt.Printf("  %s %s  status=%s  channel=%s\n", evt.Amount, evt.Currency, evt.Status, evt.Channel)

	if evt.IsTest {
		// Orders made with a test key do fire real webhooks (that is how you exercise the
		// integration), but no real money moved.
		fmt.Println("  ⚠ is_test=true: this is a test order — do not ship anything.")
	}

	switch evt.Event {
	case "payment.succeeded":
		if evt.IsTest {
			break
		}
		fmt.Println("  → Ship goods / grant entitlements here (treat amounts as decimal strings, never floats)")
	case "payment.failed":
		fmt.Println("  → Mark the order failed here")
	case "payment.refunded":
		// refunded_amount is the CUMULATIVE refunded total, not the amount of this refund;
		// evt.Amount is the ORDER TOTAL. Computing a refund from it would read "1 refunded
		// on a 1000 order" as "1000 refunded".
		//
		// Move your recorded total FORWARD ONLY — never add, and never assign blindly.
		// Delivery is at-least-once and arrival order is not guaranteed: deliveries are not
		// serialized per order, and a failed one is retried after a backoff, so the event
		// carrying 30 can land AFTER the one carrying 50. The late 30 is not a duplicate
		// (different key, correctly processed), so assigning would regress the total from 50
		// back to 30 and under-refund the customer; adding would over-refund on a redelivery.
		// max() is idempotent AND order-safe. Compare as decimals, not floats or strings
		// ("9.90" > "10.00" lexicographically). See ../../spec/SIGNING.md §3.1.
		refunded := evt.RefundedAmount
		if refunded == "" {
			refunded = "0"
		}
		fmt.Printf("  → Refunded so far %s of order total %s %s (status=%s; partially_refunded means more may follow)\n",
			refunded, evt.Amount, evt.Currency, evt.Status)
		fmt.Println("  → Advance your recorded refunded total to max(recorded, refunded_amount) — never assign blindly, and never add")
	}

	// Return 2xx quickly; anything else is retried by fluxa with exponential backoff (up to
	// 8 attempts).
	writeOK(w, "ok")
}

func writeOK(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, body)
}

func main() {
	cfg, err := fluxa.LoadConfig()
	if err != nil {
		fatal(err)
	}
	if err := cfg.RequireWebhookSecret(); err != nil {
		fatal(err)
	}

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.WebhookPort),
		Handler:           &handler{secret: cfg.WebhookSecret, processed: &dedupe{seen: map[string]struct{}{}}},
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("fluxa webhook receiver listening on http://localhost:%d\n", cfg.WebhookPort)
	fmt.Println("Point your portal callback URL here (it must be publicly reachable — use a tunnel such as ngrok for local testing).")
	if err := srv.ListenAndServe(); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
