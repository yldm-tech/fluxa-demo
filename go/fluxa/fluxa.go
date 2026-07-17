// Package fluxa is a fluxa merchant API client: HMAC signing + charge + order lookup +
// webhook verification.
// Zero dependencies — only the Go standard library (crypto/hmac, crypto/sha256, crypto/aes,
// net/http, encoding/json).
//
// The signing scheme is specified in ../../spec/SIGNING.md and pinned by ../../spec/vectors.json.
package fluxa

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxResponseBytes caps how much of a response we read — a demo should not be OOM-able
// by a misbehaving upstream.
const maxResponseBytes = 4 << 20

// canonicalQuery matches the server's canonical-query normalization (see
// ../../spec/SIGNING.md §1.1): split the raw query on "&", sort the fragments by UTF-8 byte
// order, rejoin with "&". Empty query -> "".
// sort.Strings compares Go strings byte-wise, which IS UTF-8 byte order — the exact
// ordering the server uses, for every possible input, so no custom comparator is needed.
func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

// Canonical builds the 5-line string-to-sign. The third line is CANONICAL_QUERY and
// is an EMPTY LINE when there is no query — dropping it yields a 4-line string whose
// HMAC the server rejects as bad_signature.
func Canonical(method, path, rawQuery, timestamp, body string) string {
	bodyHash := sha256.Sum256([]byte(body))
	return strings.Join([]string{
		strings.ToUpper(method),
		path,
		canonicalQuery(rawQuery),
		timestamp,
		hex.EncodeToString(bodyHash[:]),
	}, "\n")
}

// Sign returns lowercase hex(HMAC_SHA256(secret, data)).
func Sign(secret, data string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignedHeaders computes the three auth headers. `path` may carry a query string;
// it is split and folded into the signature exactly as the server does.
func SignedHeaders(keyID, secret, method, path, body string, now time.Time) map[string]string {
	ts := strconv.FormatInt(now.Unix(), 10)
	reqPath, rawQuery := path, ""
	if i := strings.Index(path, "?"); i >= 0 {
		reqPath, rawQuery = path[:i], path[i+1:]
	}
	return map[string]string{
		"X-Api-Key":   keyID,
		"X-Timestamp": ts,
		"X-Signature": Sign(secret, Canonical(method, reqPath, rawQuery, ts, body)),
	}
}

// Client is the merchant API client; it signs every request with the key pair from the config.
type Client struct {
	cfg  Config
	http *http.Client
}

// NewClient builds a client from the given config.
func NewClient(cfg Config) *Client {
	return &Client{cfg: cfg, http: &http.Client{Timeout: 30 * time.Second}}
}

// APIError is a non-2xx response from the server. fluxa's error body looks like
// {"error":{"code":"bad_signature","message":"..."}}.
type APIError struct {
	Status int
	Method string
	Path   string
	Detail string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("HTTP %d %s %s: %s", e.Status, e.Method, e.Path, e.Detail)
}

// Request signs and sends one Merchant API call, decoding a 2xx body into out
// (out may be nil). The body is marshaled ONCE and the exact same bytes are both
// hashed into the signature and written to the wire — re-marshaling could change
// key order or escaping and invalidate the signature.
func (c *Client) Request(ctx context.Context, method, path string, payload, out any) error {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to serialize request body: %w", err)
		}
	}

	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), c.cfg.BaseURL+path, reader)
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}
	for k, v := range SignedHeaders(c.cfg.KeyID, c.cfg.Secret, method, path, string(body), time.Now()) {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s request failed: %w", method, path, err)
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return &APIError{Status: res.StatusCode, Method: strings.ToUpper(method), Path: path, Detail: errorDetail(raw)}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("HTTP %d: response is not valid JSON: %s", res.StatusCode, truncate(raw, 300))
	}
	return nil
}

// errorDetail pulls the "error" field out of the body; if the shape is unexpected it echoes
// the body verbatim, which is more useful when debugging.
func errorDetail(raw []byte) string {
	var wrapper struct {
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &wrapper); err == nil && len(wrapper.Error) > 0 {
		return string(wrapper.Error)
	}
	return truncate(raw, 300)
}

func truncate(raw []byte, n int) string {
	if len(raw) > n {
		return string(raw[:n])
	}
	return string(raw)
}

// Order is an order. Amounts are always decimal strings — the server stores numeric(38,18)
// and uses decimal arithmetic, so never parse them into a float64.
type Order struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
}

// Payment is the channel-side payment record for an order.
type Payment struct {
	ID          string `json:"id"`
	ChannelCode string `json:"channel_code"`
}

// Instruction is the payer instruction. Type decides how to drive the payer:
// redirect / crypto_address / client_secret / none.
type Instruction struct {
	Type string `json:"type"`
	// type=redirect
	RedirectURL string `json:"redirect_url"`
	// type=crypto_address
	Chain                 string `json:"chain"`
	Asset                 string `json:"asset"`
	DepositAddress        string `json:"deposit_address"`
	AmountDue             string `json:"amount_due"`
	RequiredConfirmations int    `json:"required_confirmations"`
	// type=client_secret
	ClientSecret string `json:"client_secret"`
}

// ChargeRequest is the POST /api/v1/charges request body.
type ChargeRequest struct {
	// MerchantOrderID is the idempotency key: re-sending the same value returns the same
	// order (idempotent: true) instead of creating a second charge.
	MerchantOrderID string `json:"merchant_order_id"`
	// Amount is a decimal string — never a float.
	Amount           string            `json:"amount"`
	Currency         string            `json:"currency"`
	Channel          string            `json:"channel"`
	Subject          string            `json:"subject,omitempty"`
	Description      string            `json:"description,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	ReturnURL        string            `json:"return_url,omitempty"`
	CancelURL        string            `json:"cancel_url,omitempty"`
	ExpiresInSeconds int               `json:"expires_in_seconds,omitempty"`
}

// ChargeResponse is the POST /api/v1/charges response.
type ChargeResponse struct {
	Order       Order       `json:"order"`
	Payment     Payment     `json:"payment"`
	Instruction Instruction `json:"instruction"`
	Idempotent  bool        `json:"idempotent"`
}

// OrderResponse is the GET /api/v1/orders/{id} response.
type OrderResponse struct {
	Order Order `json:"order"`
}

// Event is the webhook event body fluxa POSTs to your callback URL. Fields: see
// ../../spec/SIGNING.md §3.
type Event struct {
	Event           string `json:"event"`
	OrderID         string `json:"order_id"`
	MerchantOrderID string `json:"merchant_order_id"`
	// Amount is the ORDER TOTAL, not the amount of this refund.
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
	// Status is one of paid / failed / refunded / partially_refunded.
	Status  string `json:"status"`
	Channel string `json:"channel"`
	// IsTest = true means a test order: no real money moved, so do not ship anything.
	// Test-key orders do fire real webhooks, which is how you exercise the integration.
	IsTest bool `json:"is_test"`
	// RefundedAmount is the CUMULATIVE refunded total (not the amount of this refund). It is
	// present only once something has been refunded — with no refund the field is absent from
	// the JSON and unmarshals to the zero value, an empty string. See SIGNING.md §3.1.
	RefundedAmount string `json:"refunded_amount"`
	PaidAt         string `json:"paid_at"`
}

// CreateCharge creates a charge.
func (c *Client) CreateCharge(ctx context.Context, charge ChargeRequest) (*ChargeResponse, error) {
	var out ChargeResponse
	if err := c.Request(ctx, http.MethodPost, "/api/v1/charges", charge, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetOrder reads an order back. orderID is escaped before being joined into the path — the
// signature covers the escaped path, exactly as sent.
func (c *Client) GetOrder(ctx context.Context, orderID string) (*OrderResponse, error) {
	var out OrderResponse
	path := "/api/v1/orders/" + url.PathEscape(orderID)
	if err := c.Request(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyWebhook checks X-Fluxa-Signature over "<timestamp>.<rawBody>". rawBody MUST be
// the exact received bytes — a re-serialized struct will not match. []byte -> string
// conversion in Go is byte-exact (no UTF-8 validation or replacement), so the string
// concat below hashes the received bytes verbatim.
//
// hmac.Equal is constant time and length safe, so an empty or short signature is
// rejected without leaking where the mismatch is.
func VerifyWebhook(webhookSecret, timestamp string, rawBody []byte, provided string) bool {
	expected := Sign(webhookSecret, timestamp+"."+string(rawBody))
	return hmac.Equal([]byte(expected), []byte(provided))
}

// envelope is the encrypted callback envelope: {"alg":"A256GCM","data":"<base64(nonce||ct||tag)>"}.
type envelope struct {
	Alg  string `json:"alg"`
	Data string `json:"data"`
}

// DecryptWebhook opens the AES-256-GCM envelope sent when the platform runs with
// WEBHOOK_ENCRYPTION=true. Key = SHA256(webhook_secret); blob = nonce[12] || ct || tag[16].
// Verify the signature BEFORE calling this — the signature covers the envelope.
func DecryptWebhook(webhookSecret string, envelopeJSON []byte) ([]byte, error) {
	var env envelope
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return nil, fmt.Errorf("envelope is not valid JSON: %w", err)
	}
	blob, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, fmt.Errorf("envelope data is not valid base64: %w", err)
	}

	key := sha256.Sum256([]byte(webhookSecret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Go's GCM keeps the 16-byte tag appended to the ciphertext, so blob[nonceSize:]
	// goes into Open as-is; aad is nil, matching how the server seals the envelope.
	if len(blob) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("envelope ciphertext is too short")
	}
	nonce, ciphertext := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong key or tampered ciphertext): %w", err)
	}
	return plaintext, nil
}
