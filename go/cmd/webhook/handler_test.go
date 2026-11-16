package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"fluxademo/fluxa"
)

func TestReceiverUsesAuthenticatedIdentity(t *testing.T) {
	const secret = "fixture-webhook-secret"
	for _, encrypted := range []bool{false, true} {
		t.Run(strconv.FormatBool(encrypted), func(t *testing.T) {
			h := &handler{secret: secret, processed: &dedupe{seen: map[string]struct{}{}}}
			send := func(payload, headerID string, validSignature bool) *httptest.ResponseRecorder {
				body := []byte(payload)
				if encrypted {
					key := sha256.Sum256([]byte(secret))
					block, err := aes.NewCipher(key[:])
					if err != nil {
						t.Fatal(err)
					}
					gcm, err := cipher.NewGCM(block)
					if err != nil {
						t.Fatal(err)
					}
					// A deterministic nonce is only for this offline fixture; production senders generate random nonces.
					nonce := make([]byte, gcm.NonceSize())
					blob := gcm.Seal(nonce, nonce, body, nil)
					body, err = json.Marshal(map[string]string{"alg": "A256GCM", "data": base64.StdEncoding.EncodeToString(blob)})
					if err != nil {
						t.Fatal(err)
					}
				}
				ts := strconv.FormatInt(time.Now().Unix(), 10)
				r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
				r.Header.Set("X-Fluxa-Timestamp", ts)
				r.Header.Set("X-Fluxa-Event-Id", headerID)
				r.Header.Set("X-Fluxa-Signature", fluxa.Sign(secret, ts+"."+string(body)))
				if encrypted {
					r.Header.Set("X-Fluxa-Encryption", "A256GCM")
				}
				if !validSignature {
					r.Header.Set("X-Fluxa-Signature", "invalid")
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			const first = `{"event_id":"whk_first","event":"payment.additional_received","order_id":"ord_1","amount":"100","received_amount":"110","is_test":true}`
			if w := send(first, "whk_header", false); w.Code != 401 || len(h.processed.seen) != 0 {
				t.Fatal("invalid signatures must not claim identities", w.Code)
			}
			for _, payload := range []string{`{}`, `{"event_id":""}`, `{"event_id":null}`, `{"event_id":123}`, `[]`, `null`} {
				if w := send(payload, "whk_header_only", true); w.Code != 400 || len(h.processed.seen) != 0 {
					t.Fatalf("invalid body identity accepted: %s, %d", payload, w.Code)
				}
			}
			if w := send(first, "whk_forged_header", true); w.Code != 200 || strings.Contains(w.Body.String(), "duplicate") {
				t.Fatal("first signed event should be accepted")
			}
			if w := send(first, "whk_another_header", true); w.Code != 200 || !strings.Contains(w.Body.String(), "duplicate") {
				t.Fatal("changing unsigned header must not bypass deduplication")
			}
			second := strings.Replace(first, "whk_first", "whk_second", 1)
			if w := send(second, "whk_another_header", true); w.Code != 200 || strings.Contains(w.Body.String(), "duplicate") {
				t.Fatal("distinct signed identity must survive identical business fields")
			}
			if len(h.processed.seen) != 2 {
				t.Fatal("only authenticated body identities should be stored", h.processed.seen)
			}
		})
	}
}
