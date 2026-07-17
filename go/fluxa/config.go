// Loads the shared .env from the repo root — every language demo is driven by that one
// file, so do not add a second copy under go/.
// Real process env wins over .env, so `FLUXA_CHANNEL=stripe go run ./cmd/charge` works.
package fluxa

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config holds the demo's runtime settings; the fields map one-to-one onto .env.example.
type Config struct {
	BaseURL string
	KeyID   string
	Secret  string
	// WebhookSecret verifies callback signatures. It is a DIFFERENT secret from the API
	// Secret above.
	WebhookSecret string
	Channel       string
	Currency      string
	// Amount stays a decimal string — never parse it into a float64.
	Amount      string
	WebhookPort int
}

// parseEnv is a minimal .env parser (kept in-tree to stay dependency-free): skip blank
// lines and # comments, split on the first =, and strip one matching pair of quotes.
func parseEnv(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		eq := strings.Index(t, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(t[:eq])
		val := strings.TrimSpace(t[eq+1:])
		if len(val) >= 2 {
			if (strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`)) ||
				(strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'")) {
				val = val[1 : len(val)-1]
			}
		}
		out[key] = val
	}
	return out
}

// envFilePath locates the shared .env in the repo root: walk up from the working directory
// to this module's root (the directory holding go.mod), then take its parent. Anchoring on
// go.mod rather than searching upward for a .env keeps the result deterministic — it cannot
// pick up an unrelated .env from some parent directory, and it resolves to the same file
// whether you run from go/ or go/cmd/charge.
// Fallback: if the module root is not found (e.g. a compiled binary copied elsewhere), look
// in the current directory.
func envFilePath() string {
	dir, err := os.Getwd()
	if err != nil {
		return ".env"
	}
	for i := 0; i < 8; i++ {
		if st, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !st.IsDir() {
			return filepath.Join(filepath.Dir(dir), ".env")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ".env"
}

// LoadConfig reads the shared .env and merges it with the real process environment, which
// takes precedence.
func LoadConfig() (Config, error) {
	path := envFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("%s not found — run cp .env.example .env in the repo root and fill in your keys", path)
	}
	fileEnv := parseEnv(string(data))

	// LookupEnv (not Getenv) mirrors JS `process.env[k] ?? fileEnv[k] ?? fallback`:
	// a real env var that is set-but-empty still wins over the file, and then trips
	// the required-check below.
	get := func(key, fallback string) string {
		if v, ok := os.LookupEnv(key); ok {
			return v
		}
		if v, ok := fileEnv[key]; ok {
			return v
		}
		return fallback
	}

	portRaw := get("WEBHOOK_PORT", "9000")
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return Config{}, fmt.Errorf("WEBHOOK_PORT is not a valid port number (current value: %s)", portRaw)
	}

	return Config{
		BaseURL:       strings.TrimRight(get("FLUXA_BASE_URL", "http://localhost:8090"), "/"),
		KeyID:         get("FLUXA_KEY_ID", ""),
		Secret:        get("FLUXA_SECRET", ""),
		WebhookSecret: get("FLUXA_WEBHOOK_SECRET", ""),
		Channel:       get("FLUXA_CHANNEL", "mock"),
		Currency:      get("FLUXA_CURRENCY", "USD"),
		Amount:        get("FLUXA_AMOUNT", "9.99"),
		WebhookPort:   port,
	}, nil
}

// RequireAPIKeys validates the API key pair before charging. Checking on demand (rather
// than eagerly in LoadConfig) lets the webhook demo start without API keys filled in,
// matching the lazy getters in the Node demo's config.js.
func (c Config) RequireAPIKeys() error {
	if err := requireValue("FLUXA_KEY_ID", c.KeyID); err != nil {
		return err
	}
	return requireValue("FLUXA_SECRET", c.Secret)
}

// RequireWebhookSecret validates the webhook secret before receiving callbacks.
func (c Config) RequireWebhookSecret() error {
	return requireValue("FLUXA_WEBHOOK_SECRET", c.WebhookSecret)
}

func requireValue(key, val string) error {
	if val != "" && !strings.HasSuffix(val, "replace_me") {
		return nil
	}
	shown := val
	if shown == "" {
		shown = "unset"
	}
	return fmt.Errorf("%s is not filled in in .env (current value: %s)", key, shown)
}
