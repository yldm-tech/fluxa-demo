// Loads the shared .env from the repo root. Every language demo reads that one file —
// do not create a second copy under rust/.
// Real process env wins over .env, so `FLUXA_CHANNEL=stripe cargo run --bin charge` works.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;

/// Config holds the demo's runtime settings; the field names map one-to-one onto
/// .env.example.
#[derive(Debug, Clone)]
pub struct Config {
    pub base_url: String,
    pub key_id: String,
    pub secret: String,
    /// webhook_secret verifies callback signatures. It is a DIFFERENT secret from the API
    /// secret above.
    pub webhook_secret: String,
    pub channel: String,
    pub currency: String,
    /// amount stays a decimal string — never parse it as f64.
    pub amount: String,
    pub webhook_port: u16,
}

/// parse_env is a minimal .env parser (so there is no dotenv crate to pull in): skip blank
/// lines and # comments, split on the first =, and strip one matching pair of surrounding
/// quotes from the value.
fn parse_env(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some(eq) = t.find('=') else { continue };
        let key = t[..eq].trim().to_string();
        let mut val = t[eq + 1..].trim();
        if val.len() >= 2
            && ((val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\'')))
        {
            val = &val[1..val.len() - 1];
        }
        out.insert(key, val.to_string());
    }
    out
}

/// env_file_path locates the shared .env at the repo root. CARGO_MANIFEST_DIR is a
/// compile-time constant (the absolute path of rust/), so its parent is the repo root:
/// `cargo run` from any directory resolves to the same file, and it can never accidentally
/// pick up an unrelated .env from some parent directory.
/// parent() is used rather than join("..") so error messages show a clean absolute path
/// instead of `rust/../.env`.
fn env_file_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap_or(&manifest)
        .join(".env")
}

/// load reads the shared .env and merges it with the real process environment, which wins.
pub fn load() -> Result<Config, String> {
    let path = env_file_path();
    let text = fs::read_to_string(&path).map_err(|_| {
        format!(
            "{} not found — run `cp .env.example .env` at the repo root and fill in your keys.",
            path.display()
        )
    })?;
    let file_env = parse_env(&text);

    // env::var (which errors only when unset) mirrors JS `process.env[k] ?? fileEnv[k] ??
    // fallback`: a real env var that is set-but-empty still wins over the file, and then
    // trips the required-check below.
    let get = |key: &str, fallback: &str| -> String {
        env::var(key).unwrap_or_else(|_| {
            file_env
                .get(key)
                .cloned()
                .unwrap_or_else(|| fallback.to_string())
        })
    };

    let port_raw = get("WEBHOOK_PORT", "9000");
    let webhook_port = port_raw
        .parse::<u16>()
        .map_err(|_| format!("WEBHOOK_PORT is not a valid port number (got: {port_raw})"))?;

    Ok(Config {
        base_url: get("FLUXA_BASE_URL", "http://localhost:8090")
            .trim_end_matches('/')
            .to_string(),
        key_id: get("FLUXA_KEY_ID", ""),
        secret: get("FLUXA_SECRET", ""),
        webhook_secret: get("FLUXA_WEBHOOK_SECRET", ""),
        channel: get("FLUXA_CHANNEL", "mock"),
        currency: get("FLUXA_CURRENCY", "USD"),
        amount: get("FLUXA_AMOUNT", "9.99"),
        webhook_port,
    })
}

impl Config {
    /// require_api_keys checks the API key pair before creating a charge. Checking on
    /// demand — rather than validating everything up front in load() — is what lets the
    /// webhook demo run without API keys set, mirroring the Node demo's lazy getters.
    pub fn require_api_keys(&self) -> Result<(), String> {
        require_value("FLUXA_KEY_ID", &self.key_id)?;
        require_value("FLUXA_SECRET", &self.secret)
    }

    /// require_webhook_secret checks the webhook secret before receiving callbacks.
    pub fn require_webhook_secret(&self) -> Result<(), String> {
        require_value("FLUXA_WEBHOOK_SECRET", &self.webhook_secret)
    }
}

fn require_value(key: &str, val: &str) -> Result<(), String> {
    if !val.is_empty() && !val.ends_with("replace_me") {
        return Ok(());
    }
    let shown = if val.is_empty() { "unset" } else { val };
    Err(format!("{key} is not filled in yet in .env (current value: {shown})."))
}
