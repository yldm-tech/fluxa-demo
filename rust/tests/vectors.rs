// Known-answer tests: this implementation must reproduce ../../spec/vectors.json byte for
// byte. Those vectors are generated from fluxa's actual server-side signing code, which
// makes them the single criterion for a correct port — and checking them needs no running
// server and no credentials.
//
//   cargo test

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use fluxa::{canonical, decrypt_webhook, sign, signed_headers, verify_webhook};

#[derive(Deserialize)]
struct VectorFile {
    envelopes: Vec<EnvelopeVector>,
    requests: Vec<RequestVector>,
    webhooks: Vec<WebhookVector>,
}

#[derive(Deserialize)]
struct EnvelopeVector {
    name: String,
    secret: String,
    envelope: String,
    plaintext: String,
}

#[derive(Deserialize)]
struct RequestVector {
    name: String,
    method: String,
    path: String,
    raw_query: String,
    timestamp: String,
    body: String,
    secret: String,
    canonical: String,
    signature: String,
}

#[derive(Deserialize)]
struct WebhookVector {
    name: String,
    timestamp: String,
    body: String,
    secret: String,
    signed_raw: String,
    signature: String,
}

/// CARGO_MANIFEST_DIR is a compile-time constant (= rust/), so the vectors file resolves
/// independently of the current working directory.
fn load_vectors() -> VectorFile {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest
        .parent()
        .unwrap_or(&manifest)
        .join("spec")
        .join("vectors.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read vectors file {}: {e}", path.display()));
    let v: VectorFile =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("vectors file is not valid JSON: {e}"));
    assert!(
        !v.requests.is_empty() && !v.webhooks.is_empty() && !v.envelopes.is_empty(),
        "vectors file is missing requests / webhooks / envelopes"
    );
    v
}

#[test]
fn request_vectors() {
    for v in load_vectors().requests {
        let canon = canonical(&v.method, &v.path, &v.raw_query, &v.timestamp, &v.body);
        assert_eq!(canon, v.canonical, "[{}] canonical string mismatch", v.name);
        assert_eq!(
            sign(&v.secret, &canon),
            v.signature,
            "[{}] signature mismatch",
            v.name
        );
    }
}

#[test]
fn canonical_no_query_keeps_empty_third_line() {
    // With no query, line 3 of the canonical must still be present as an empty line —
    // 5 lines, not 4. Dropping it is the single most common integration failure.
    let canon = canonical("POST", "/api/v1/charges", "", "1750000000", "{}");
    let lines: Vec<&str> = canon.split('\n').collect();
    assert_eq!(lines.len(), 5, "canonical must be 5 lines, got: {canon:?}");
    assert_eq!(
        lines[2], "",
        "line 3 (CANONICAL_QUERY) must be the empty string"
    );
}

#[test]
fn query_order_does_not_change_signature_but_tampering_does() {
    let a = canonical("GET", "/api/v1/orders", "status=paid&limit=10", "1750000000", "");
    let b = canonical("GET", "/api/v1/orders", "limit=10&status=paid", "1750000000", "");
    assert_eq!(a, b, "different param order must give the same canonical");
    assert_eq!(
        sign("sk_x", &a),
        sign("sk_x", &b),
        "different param order must give the same signature"
    );

    let tampered = canonical("GET", "/api/v1/orders", "status=failed&limit=10", "1750000000", "");
    assert_ne!(a, tampered, "tampering with a param value must change the canonical");

    let dropped = canonical("GET", "/api/v1/orders", "", "1750000000", "");
    assert_ne!(a, dropped, "dropping the query must change the canonical");
}

/// Query fragments sort in UTF-8 byte order, matching the server. Are the UTF-8 bytes of
/// U+FFFF (ef bf bf) greater than those of U+1F600 😀 (f0 9f 98 80)? No — ef < f0, so ￿
/// sorts first. Compare by UTF-16 code unit instead and 😀 is the surrogate pair d83d dc00;
/// since d83d < ffff, 😀 would sort first and the signature would diverge from the server's.
/// This is the only vector that catches a wrong comparator — every other query vector is
/// ASCII, where all comparators agree.
#[test]
fn query_sorts_by_utf8_byte_order_not_utf16() {
    let v = load_vectors()
        .requests
        .into_iter()
        .find(|r| r.name == "get_query_utf16_divergence")
        .expect("vectors file is missing get_query_utf16_divergence");

    let canon = canonical(&v.method, &v.path, &v.raw_query, &v.timestamp, &v.body);
    assert_eq!(canon, v.canonical, "UTF-8 byte-order sort mismatch");
    assert_eq!(sign(&v.secret, &canon), v.signature);

    // Send the fragments in the opposite order: the canonical must still put ￿ first.
    let flipped = canonical(&v.method, &v.path, "k=😀&k=￿", &v.timestamp, &v.body);
    assert_eq!(
        flipped, v.canonical,
        "reversed input must sort back to the same canonical"
    );
}

#[test]
fn signed_headers_folds_query_from_path() {
    let h = signed_headers(
        "pk_x",
        "sk_x",
        "GET",
        "/api/v1/orders?status=paid&limit=10",
        "",
        1750000000,
    );
    let want = sign(
        "sk_x",
        &canonical("GET", "/api/v1/orders", "status=paid&limit=10", "1750000000", ""),
    );
    assert_eq!(h.signature, want);
    assert_eq!(h.timestamp, "1750000000");
    assert_eq!(h.api_key, "pk_x");
}

#[test]
fn webhook_vectors() {
    for w in load_vectors().webhooks {
        assert_eq!(
            sign(&w.secret, &w.signed_raw),
            w.signature,
            "[{}] signature mismatch",
            w.name
        );
        assert!(
            verify_webhook(&w.secret, &w.timestamp, w.body.as_bytes(), &w.signature),
            "[{}] should verify",
            w.name
        );
        assert!(
            !verify_webhook(
                &w.secret,
                &w.timestamp,
                format!("{}x", w.body).as_bytes(),
                &w.signature
            ),
            "[{}] a tampered body must be rejected",
            w.name
        );
        assert!(
            !verify_webhook("wrong_secret", &w.timestamp, w.body.as_bytes(), &w.signature),
            "[{}] a wrong secret must be rejected",
            w.name
        );
        assert!(
            !verify_webhook(&w.secret, &w.timestamp, w.body.as_bytes(), ""),
            "[{}] an empty signature must be rejected",
            w.name
        );
    }
}

#[test]
fn envelope_vectors() {
    for e in load_vectors().envelopes {
        let got = decrypt_webhook(&e.secret, e.envelope.as_bytes())
            .unwrap_or_else(|err| panic!("[{}] decryption failed: {err}", e.name));
        assert_eq!(
            String::from_utf8_lossy(&got),
            e.plaintext,
            "[{}] plaintext mismatch",
            e.name
        );
        assert!(
            decrypt_webhook("wrong_secret", e.envelope.as_bytes()).is_err(),
            "[{}] a wrong secret must fail to decrypt",
            e.name
        );
    }
}
