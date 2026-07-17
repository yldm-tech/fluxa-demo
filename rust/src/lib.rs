// fluxa merchant API client: HMAC request signing + charge + order lookup + webhook
// verification.
//
// Rust's standard library ships neither crypto nor HTTP, so this demo cannot be
// dependency-free the way the node/go ones are. It sticks to RustCrypto
// (hmac/sha2/aes-gcm) + serde + ureq; the rationale for each crate is in README.md.
//
// The signing contract is ../../spec/SIGNING.md, pinned by ../../spec/vectors.json.

pub mod config;

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use config::Config;

type HmacSha256 = Hmac<Sha256>;

/// maxResponseBytes caps how much of a response we read — a demo should not be OOM-able
/// by a misbehaving upstream.
const MAX_RESPONSE_BYTES: u64 = 4 << 20;

/// The fixed-size parts of the AES-256-GCM envelope: nonce[12] || ciphertext || tag[16].
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

// canonical_query matches the server's canonical-query normalization (see
// ../../spec/SIGNING.md §1.1): split the raw query on "&", sort the fragments by UTF-8
// byte order, rejoin with "&". Empty query -> "".
//
// `Ord for str` compares Rust strings byte-wise, and Rust strings are always UTF-8 — so a
// plain sort() IS UTF-8 byte order, matching the server for every possible input. No
// custom comparator needed, which is a Rust-specific piece of luck: JS and Java default
// to UTF-16 order and diverge on raw code points above U+FFFF, and C# defaults to
// culture-sensitive order, which is wrong even for ASCII in some locales.
//
// str::split('&') keeps empty fragments — it does not drop trailing empties the way
// Ruby's default split (or Java's one-arg String.split) does, which is what the server
// expects.
fn canonical_query(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let mut parts: Vec<&str> = raw.split('&').collect();
    parts.sort_unstable();
    parts.join("&")
}

/// canonical builds the 5-line string-to-sign. The third line is CANONICAL_QUERY and
/// is an EMPTY LINE when there is no query — dropping it yields a 4-line string whose
/// HMAC the server rejects as bad_signature.
pub fn canonical(method: &str, path: &str, raw_query: &str, timestamp: &str, body: &str) -> String {
    let method = method.to_uppercase();
    let query = canonical_query(raw_query);
    let body_hash = hex::encode(Sha256::digest(body.as_bytes()));
    [
        method.as_str(),
        path,
        query.as_str(),
        timestamp,
        body_hash.as_str(),
    ]
    .join("\n")
}

/// sign returns lowercase hex(HMAC_SHA256(secret, data)).
pub fn sign(secret: &str, data: &str) -> String {
    let mut mac = new_mac(secret);
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

// HMAC accepts a key of any length (it pads or hashes it down), so new_from_slice
// never actually fails for Hmac<Sha256> — the Err arm is unreachable. The qualified
// `as Mac` picks hmac's constructor over the aead::KeyInit one also in scope here.
fn new_mac(secret: &str) -> HmacSha256 {
    <HmacSha256 as Mac>::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length")
}

/// SignedHeaders holds the three auth headers for one request.
pub struct SignedHeaders {
    pub api_key: String,
    pub timestamp: String,
    pub signature: String,
}

impl SignedHeaders {
    /// Yields (name, value) pairs to set on the HTTP client one by one.
    pub fn as_pairs(&self) -> [(&'static str, &str); 3] {
        [
            ("X-Api-Key", &self.api_key),
            ("X-Timestamp", &self.timestamp),
            ("X-Signature", &self.signature),
        ]
    }
}

/// signed_headers computes the three auth headers. `path` may carry a query string;
/// it is split and folded into the signature exactly as the server does.
pub fn signed_headers(
    key_id: &str,
    secret: &str,
    method: &str,
    path: &str,
    body: &str,
    now_seconds: u64,
) -> SignedHeaders {
    let ts = now_seconds.to_string();
    let (req_path, raw_query) = match path.find('?') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => (path, ""),
    };
    SignedHeaders {
        signature: sign(secret, &canonical(method, req_path, raw_query, &ts, body)),
        api_key: key_id.to_string(),
        timestamp: ts,
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs()
}

/// Error covers the three classes of failure this client returns.
#[derive(Debug)]
pub enum Error {
    /// Api is a non-2xx response from the server. fluxa's error body looks like
    /// {"error":{"code":"bad_signature","message":"..."}}.
    Api {
        status: u16,
        method: String,
        path: String,
        detail: String,
    },
    /// Http is a transport-level failure: connection refused, timeout, and so on.
    Http(String),
    /// Decode is a serialization, deserialization, or decryption failure.
    Decode(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Api {
                status,
                method,
                path,
                detail,
            } => write!(f, "HTTP {status} {method} {path}: {detail}"),
            Error::Http(msg) | Error::Decode(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Error {}

/// Client is the merchant API client. It signs every request with the key pair from config.
pub struct Client {
    cfg: Config,
    agent: ureq::Agent,
}

impl Client {
    /// Builds a client from config.
    pub fn new(cfg: Config) -> Self {
        // http_status_as_error(false): by default ureq turns 4xx/5xx into an Err, which
        // throws away the response body. Turning it off is what lets us surface fluxa's
        // {"error":{"code":"bad_signature"}} to the user verbatim.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .build()
            .into();
        Self { cfg, agent }
    }

    /// request signs and sends one Merchant API call, decoding a 2xx body into T.
    ///
    /// `body` is an **already-serialized** string: the same bytes feed the signature hash
    /// and go out on the wire. The caller is responsible for serializing exactly once —
    /// re-serializing after signing can change key order or escaping, and any such
    /// difference invalidates the signature. (That is why this does not use ureq's
    /// send_json: it would serialize a second time itself.)
    fn request<T: DeserializeOwned>(&self, method: &str, path: &str, body: &str) -> Result<T, Error> {
        let method = method.to_uppercase();
        let url = format!("{}{}", self.cfg.base_url, path);
        let headers = signed_headers(
            &self.cfg.key_id,
            &self.cfg.secret,
            &method,
            path,
            body,
            now_seconds(),
        );

        let mut builder = ureq::http::Request::builder()
            .method(method.as_str())
            .uri(&url)
            .header("Content-Type", "application/json");
        for (name, value) in headers.as_pairs() {
            builder = builder.header(name, value);
        }

        // An empty body is sent as () rather than "": a GET may not carry a request body,
        // and ureq rejects one outright with BodyNotAllowed. The signature is unaffected —
        // line 5 of the canonical is the hash of the empty string either way (always
        // e3b0c442…).
        let sent = if body.is_empty() {
            let req = builder
                .body(())
                .map_err(|e| Error::Http(format!("failed to build request: {e}")))?;
            self.agent.run(req)
        } else {
            let req = builder
                .body(body)
                .map_err(|e| Error::Http(format!("failed to build request: {e}")))?;
            self.agent.run(req)
        };
        let mut res = sent.map_err(|e| Error::Http(format!("{method} {path} request failed: {e}")))?;

        let status = res.status().as_u16();
        let raw = res
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_vec()
            .map_err(|e| Error::Http(format!("failed to read response: {e}")))?;

        if !(200..300).contains(&status) {
            return Err(Error::Api {
                status,
                method,
                path: path.to_string(),
                detail: error_detail(&raw),
            });
        }
        serde_json::from_slice(&raw).map_err(|_| {
            Error::Decode(format!(
                "HTTP {status}: response is not valid JSON: {}",
                truncate(&raw, 300)
            ))
        })
    }

    /// Creates a charge.
    pub fn create_charge(&self, charge: &ChargeRequest) -> Result<ChargeResponse, Error> {
        // Serialize the body exactly once: the string below is both signed and sent.
        let body = serde_json::to_string(charge)
            .map_err(|e| Error::Decode(format!("failed to serialize request body: {e}")))?;
        self.request("POST", "/api/v1/charges", &body)
    }

    /// Looks an order back up. The order_id is escaped before it is joined into the path,
    /// because the signature covers the escaped path — sign the bytes you send.
    pub fn get_order(&self, order_id: &str) -> Result<OrderResponse, Error> {
        let path = format!("/api/v1/orders/{}", path_escape(order_id));
        // A GET has no body, so line 5 of the canonical is the hash of the empty string
        // (always e3b0c442…).
        self.request("GET", &path, "")
    }
}

// path_escape percent-encodes one path segment before it is signed AND sent — the two
// must be the same bytes, so escaping happens first. Everything outside RFC 3986's
// unreserved set is encoded; real fluxa ids (`ord_01k…`) are entirely unreserved, so
// for them this is a no-op.
fn path_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// error_detail pulls the `error` field out of an error body; if the body is not the
/// expected shape it is echoed back as-is, which is more useful when debugging.
fn error_detail(raw: &[u8]) -> String {
    #[derive(Deserialize)]
    struct Wrapper {
        error: serde_json::Value,
    }
    match serde_json::from_slice::<Wrapper>(raw) {
        Ok(w) => w.error.to_string(),
        Err(_) => truncate(raw, 300),
    }
}

fn truncate(raw: &[u8], n: usize) -> String {
    let text = String::from_utf8_lossy(raw);
    match text.char_indices().nth(n) {
        Some((i, _)) => text[..i].to_string(),
        None => text.into_owned(),
    }
}

/// Order is an order. Amounts are always decimal strings — the server stores
/// numeric(38,18) and uses decimal arithmetic, so never parse them as f64.
#[derive(Debug, Deserialize)]
pub struct Order {
    pub id: String,
    pub status: String,
    pub amount: String,
    pub currency: String,
}

/// Payment is this order's payment record on the channel side.
#[derive(Debug, Deserialize)]
pub struct Payment {
    pub id: String,
    pub channel_code: String,
}

/// Instruction is the payer instruction. Its `type` decides how to route the payer:
/// redirect / crypto_address / client_secret / none.
#[derive(Debug, Deserialize)]
pub struct Instruction {
    #[serde(rename = "type")]
    pub kind: String,
    // type=redirect
    #[serde(default)]
    pub redirect_url: String,
    // type=crypto_address
    #[serde(default)]
    pub chain: String,
    #[serde(default)]
    pub asset: String,
    #[serde(default)]
    pub deposit_address: String,
    #[serde(default)]
    pub amount_due: String,
    #[serde(default)]
    pub required_confirmations: i32,
    // type=client_secret
    #[serde(default)]
    pub client_secret: String,
}

/// ChargeRequest is the POST /api/v1/charges request body.
#[derive(Debug, Serialize)]
pub struct ChargeRequest {
    /// merchant_order_id is the idempotency key: re-sending the same value returns the
    /// same order (idempotent: true) rather than creating a second charge.
    pub merchant_order_id: String,
    /// amount is a decimal string — never a float.
    pub amount: String,
    pub currency: String,
    pub channel: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subject: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub metadata: std::collections::BTreeMap<String, String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub return_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cancel_url: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub expires_in_seconds: i64,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// ChargeResponse is the POST /api/v1/charges response.
#[derive(Debug, Deserialize)]
pub struct ChargeResponse {
    pub order: Order,
    pub payment: Payment,
    pub instruction: Instruction,
    #[serde(default)]
    pub idempotent: bool,
}

/// OrderResponse is the GET /api/v1/orders/{id} response.
#[derive(Debug, Deserialize)]
pub struct OrderResponse {
    pub order: Order,
}

/// Event is the body of a fluxa webhook. Field reference: ../../spec/SIGNING.md §3.
#[derive(Debug, Deserialize)]
pub struct Event {
    pub event: String,
    pub order_id: String,
    #[serde(default)]
    pub merchant_order_id: String,
    /// amount is the **order total**, not the amount refunded by this event. Computing a
    /// refund from it reads "1 refunded on a 1000 order" as "1000 refunded".
    pub amount: String,
    pub currency: String,
    /// status is one of paid / failed / refunded / partially_refunded.
    pub status: String,
    #[serde(default)]
    pub channel: String,
    #[serde(default)]
    pub paid_at: String,
    /// refunded_amount is the **cumulative** refunded total (not this event's refund), and
    /// is **present only once something has actually been refunded** — hence the Option.
    /// serde tolerates a missing Option field natively (absent => None), so no
    /// #[serde(default)] is needed here.
    pub refunded_amount: Option<String>,
    /// is_test=true marks a test order: no real money moved, so do not ship goods.
    /// Test-key orders do fire webhooks, so the integration stays exercisable.
    #[serde(default)]
    pub is_test: bool,
}

impl Event {
    /// dedupe_key is the idempotency key: `event : order_id : refunded_amount`.
    ///
    /// The key MUST include refunded_amount. `(event, order_id)` alone is **not unique**:
    /// a single order can be partially refunded more than once, and each refund fires its
    /// own payment.refunded. Deduplicating on just that pair drops the second partial
    /// refund as a "duplicate" and returns 2xx — fluxa then records the delivery as
    /// successful and never retries. The customer is under-refunded and nothing errors
    /// anywhere in the chain, which is why this is worth spelling out.
    ///
    /// refunded_amount is cumulative and strictly increasing, so it separates a redelivery
    /// of the same event (same value => deduplicate) from a genuinely new partial refund
    /// (higher value => process).
    ///
    /// payment.succeeded / payment.failed carry no refunded_amount, so for them this
    /// degrades to the old `(event, order_id)` behaviour, which is correct for those.
    ///
    /// In a real integration this belongs in a database unique constraint (a unique index
    /// on order_id + event + refunded_amount). The in-process HashSet is a demo stand-in.
    /// See ../../spec/SIGNING.md §3.1.
    pub fn dedupe_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.event,
            self.order_id,
            self.refunded_amount.as_deref().unwrap_or("")
        )
    }
}

/// verify_webhook checks X-Fluxa-Signature over "<timestamp>.<raw_body>". raw_body MUST
/// be the exact received bytes — a re-serialized struct will not match. Taking &[u8] and
/// feeding it straight into the MAC means the bytes are never round-tripped through a
/// String, so no UTF-8 validation or replacement can touch them.
///
/// verify_slice is a constant-time, length-safe compare, so a wrong, short or empty
/// signature is rejected without leaking where the mismatch is.
pub fn verify_webhook(webhook_secret: &str, timestamp: &str, raw_body: &[u8], provided: &str) -> bool {
    let mut mac = new_mac(webhook_secret);
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(raw_body);
    // X-Fluxa-Signature is lowercase hex; decode it and let verify_slice compare the raw
    // bytes. Malformed (or empty) hex fails to decode and is rejected — that early exit
    // only depends on attacker-supplied input, never on the secret.
    let Ok(provided_bytes) = hex::decode(provided) else {
        return false;
    };
    mac.verify_slice(&provided_bytes).is_ok()
}

/// Envelope is the encrypted-webhook envelope:
/// {"alg":"A256GCM","data":"<base64(nonce||ct||tag)>"}. Only `data` is read — `alg` is
/// always A256GCM, matching the X-Fluxa-Encryption header.
#[derive(Deserialize)]
struct Envelope {
    data: String,
}

/// decrypt_webhook opens the AES-256-GCM envelope sent when the platform runs with
/// WEBHOOK_ENCRYPTION=true. Key = SHA256(webhook_secret); blob = nonce[12] || ct || tag[16].
/// Verify the signature BEFORE calling this — the signature covers the envelope.
pub fn decrypt_webhook(webhook_secret: &str, envelope_json: &[u8]) -> Result<Vec<u8>, Error> {
    let env: Envelope = serde_json::from_slice(envelope_json)
        .map_err(|e| Error::Decode(format!("envelope is not valid JSON: {e}")))?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(env.data)
        .map_err(|e| Error::Decode(format!("envelope data is not valid base64: {e}")))?;

    // key = SHA256(webhook_secret): hash the secret's **raw bytes**, not a hex or base64
    // rendering of them.
    let key = Sha256::digest(webhook_secret.as_bytes());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Decode("envelope ciphertext is too short".into()));
    }
    // The aes-gcm crate expects the 16-byte tag APPENDED to the ciphertext, which is
    // exactly how the server emits it — so blob[12..] goes in whole, tag and all. This is
    // the language split worth remembering: Node, Ruby, PHP and C# instead take the tag as
    // a separate argument and need it sliced off the end. The AAD is empty.
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| Error::Decode("decryption failed (wrong key or tampered ciphertext)".into()))
}
