// Known-answer tests: this implementation must reproduce ../../spec/vectors.json byte for
// byte. Those vectors are generated from fluxa's actual server-side signing code, which
// makes them the criterion for a correct port — no running server required.
//
//	go test ./...
package fluxa

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type vectorFile struct {
	Envelopes []struct {
		Name      string `json:"name"`
		Secret    string `json:"secret"`
		Envelope  string `json:"envelope"`
		Plaintext string `json:"plaintext"`
	} `json:"envelopes"`
	Requests []struct {
		Name      string `json:"name"`
		Method    string `json:"method"`
		Path      string `json:"path"`
		RawQuery  string `json:"raw_query"`
		Timestamp string `json:"timestamp"`
		Body      string `json:"body"`
		Secret    string `json:"secret"`
		Canonical string `json:"canonical"`
		Signature string `json:"signature"`
	} `json:"requests"`
	Webhooks []struct {
		Name      string `json:"name"`
		Timestamp string `json:"timestamp"`
		Body      string `json:"body"`
		Secret    string `json:"secret"`
		SignedRaw string `json:"signed_raw"`
		Signature string `json:"signature"`
	} `json:"webhooks"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	// go test runs with the package dir as cwd, so this resolves to the repo's spec dir.
	raw, err := os.ReadFile("../../spec/vectors.json")
	if err != nil {
		t.Fatalf("failed to read the vectors file: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("the vectors file is not valid JSON: %v", err)
	}
	if len(v.Requests) == 0 || len(v.Webhooks) == 0 || len(v.Envelopes) == 0 {
		t.Fatal("the vectors file is missing requests / webhooks / envelopes")
	}
	return v
}

func TestRequestVectors(t *testing.T) {
	for _, v := range loadVectors(t).Requests {
		t.Run(v.Name, func(t *testing.T) {
			canon := Canonical(v.Method, v.Path, v.RawQuery, v.Timestamp, v.Body)
			if canon != v.Canonical {
				t.Errorf("canonical string does not match\n got: %q\nwant: %q", canon, v.Canonical)
			}
			if got := Sign(v.Secret, canon); got != v.Signature {
				t.Errorf("signature does not match\n got: %s\nwant: %s", got, v.Signature)
			}
		})
	}
}

func TestCanonicalNoQueryKeepsEmptyThirdLine(t *testing.T) {
	// With no query the canonical's 3rd line must be an empty line (5 lines, not 4).
	canon := Canonical("POST", "/api/v1/charges", "", "1750000000", "{}")
	lines := strings.Split(canon, "\n")
	if len(lines) != 5 {
		t.Fatalf("canonical must be 5 lines, got %d: %q", len(lines), canon)
	}
	if lines[2] != "" {
		t.Errorf("line 3 (CANONICAL_QUERY) must be the empty string, got %q", lines[2])
	}
}

func TestQueryOrderDoesNotChangeSignatureButTamperingDoes(t *testing.T) {
	a := Canonical("GET", "/api/v1/orders", "status=paid&limit=10", "1750000000", "")
	b := Canonical("GET", "/api/v1/orders", "limit=10&status=paid", "1750000000", "")
	if a != b {
		t.Errorf("a different parameter order must yield the same canonical\n a: %q\n b: %q", a, b)
	}
	if Sign("sk_x", a) != Sign("sk_x", b) {
		t.Error("a different parameter order must yield the same signature")
	}
	if tampered := Canonical("GET", "/api/v1/orders", "status=failed&limit=10", "1750000000", ""); a == tampered {
		t.Error("tampering with a parameter value must change the canonical")
	}
	if dropped := Canonical("GET", "/api/v1/orders", "", "1750000000", ""); a == dropped {
		t.Error("dropping the query must change the canonical")
	}
}

func TestSignedHeadersFoldsQueryFromPath(t *testing.T) {
	h := SignedHeaders("pk_x", "sk_x", "GET", "/api/v1/orders?status=paid&limit=10", "", time.Unix(1750000000, 0))
	want := Sign("sk_x", Canonical("GET", "/api/v1/orders", "status=paid&limit=10", "1750000000", ""))
	if h["X-Signature"] != want {
		t.Errorf("X-Signature = %s, want %s", h["X-Signature"], want)
	}
	if h["X-Timestamp"] != "1750000000" {
		t.Errorf("X-Timestamp = %s, want 1750000000", h["X-Timestamp"])
	}
	if h["X-Api-Key"] != "pk_x" {
		t.Errorf("X-Api-Key = %s, want pk_x", h["X-Api-Key"])
	}
}

func TestWebhookVectors(t *testing.T) {
	for _, w := range loadVectors(t).Webhooks {
		t.Run(w.Name, func(t *testing.T) {
			if got := Sign(w.Secret, w.SignedRaw); got != w.Signature {
				t.Errorf("signature does not match\n got: %s\nwant: %s", got, w.Signature)
			}
			if !VerifyWebhook(w.Secret, w.Timestamp, []byte(w.Body), w.Signature) {
				t.Error("should verify")
			}
			if VerifyWebhook(w.Secret, w.Timestamp, []byte(w.Body+"x"), w.Signature) {
				t.Error("a tampered body must be rejected")
			}
			if VerifyWebhook("wrong_secret", w.Timestamp, []byte(w.Body), w.Signature) {
				t.Error("a wrong secret must be rejected")
			}
			if VerifyWebhook(w.Secret, w.Timestamp, []byte(w.Body), "") {
				t.Error("an empty signature must be rejected")
			}
		})
	}
}

func TestEnvelopeVectors(t *testing.T) {
	for _, e := range loadVectors(t).Envelopes {
		t.Run(e.Name, func(t *testing.T) {
			got, err := DecryptWebhook(e.Secret, []byte(e.Envelope))
			if err != nil {
				t.Fatalf("decryption failed: %v", err)
			}
			if string(got) != e.Plaintext {
				t.Errorf("plaintext does not match\n got: %s\nwant: %s", got, e.Plaintext)
			}
			if _, err := DecryptWebhook("wrong_secret", []byte(e.Envelope)); err == nil {
				t.Error("a wrong secret must fail to decrypt")
			}
		})
	}
}
