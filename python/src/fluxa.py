# fluxa merchant API client: HMAC signing + charge + order lookup + webhook verification.
# Zero dependencies — only the Python standard library (hmac / hashlib / json / urllib).
#
# The signing scheme is specified in ../../spec/SIGNING.md and pinned by ../../spec/vectors.json.
#
# The single exception is the encrypted webhook envelope: the stdlib has no AES, so
# `cryptography` is imported only for that path (see decrypt_webhook). Payload encryption is
# off by default, and with it off this demo is genuinely dependency-free.
import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request

# Optional: the AES-256-GCM envelope needs a real AES implementation, which the stdlib
# does not ship. Imported lazily-ish (at module load, but tolerated missing) so that the
# signing path — everything that matters when WEBHOOK_ENCRYPTION is off — stays dependency-free.
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - depends on the environment
    AESGCM = None
    HAS_CRYPTOGRAPHY = False

# Sentinel telling "no body at all" apart from an explicit null payload, mirroring the
# JS `payload === undefined` check.
_NO_BODY = object()


def _to_bytes(value):
    """Normalize str/bytes/None to bytes. Signing always operates on bytes."""
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return value.encode("utf-8")


# canonical_query matches the server's canonical-query normalization (see
# ../../spec/SIGNING.md §1.1): split the raw query on "&", sort the fragments by UTF-8 byte
# order, rejoin with "&". Empty query -> "".
# Sorting on the encoded bytes is what the server does, for every possible input.
# (Python's default str ordering is by code point, which already agrees with UTF-8 byte
# order — unlike JS's UTF-16 ordering — but keying on the bytes states the rule outright.)
def canonical_query(raw):
    if not raw:
        return ""
    return "&".join(sorted(raw.split("&"), key=lambda frag: frag.encode("utf-8")))


# canonical builds the 5-line string-to-sign. The third line is CANONICAL_QUERY and
# is an EMPTY LINE when there is no query — dropping it yields a 4-line string whose
# HMAC the server rejects as bad_signature.
def canonical(method, path, raw_query, timestamp, body):
    body_hash = hashlib.sha256(_to_bytes(body)).hexdigest()
    return "\n".join([method.upper(), path, canonical_query(raw_query), str(timestamp), body_hash])


def sign(secret, data):
    return hmac.new(_to_bytes(secret), _to_bytes(data), hashlib.sha256).hexdigest()


# signed_headers computes the three auth headers. `path` may carry a query string;
# it is split and folded into the signature exactly as the server does.
def signed_headers(key_id, secret, method, path, body, now_seconds=None):
    ts = str(now_seconds if now_seconds is not None else int(time.time()))
    req_path, _, raw_query = path.partition("?")
    return {
        "X-Api-Key": key_id,
        "X-Timestamp": ts,
        "X-Signature": sign(secret, canonical(method, req_path, raw_query, ts, body)),
    }


# request signs and sends one Merchant API call. The body is serialized ONCE and the
# exact same bytes are both signed and sent — re-serializing would change key order
# or spacing and invalidate the signature.
def request(cfg, method, path, payload=_NO_BODY):
    if payload is _NO_BODY:
        body = b""
    else:
        # separators/ensure_ascii keep this byte-for-byte like the other demos' JSON.
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    headers = signed_headers(cfg.key_id, cfg.secret, method, path, body)
    headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        cfg.base_url + path,
        data=body if body else None,
        headers=headers,
        method=method.upper(),
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            status = res.status
            text = res.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        # urllib raises on 4xx/5xx; the error body carries fluxa's error payload.
        status = e.code
        text = e.read().decode("utf-8", "replace")

    try:
        parsed = json.loads(text) if text else None
    except ValueError:
        raise RuntimeError("HTTP {}: response is not valid JSON: {}".format(status, text[:300]))

    if not 200 <= status < 300:
        err = parsed.get("error", parsed) if isinstance(parsed, dict) else parsed
        raise RuntimeError(
            "HTTP {} {} {}: {}".format(status, method, path, json.dumps(err, ensure_ascii=False))
        )
    return parsed


def create_charge(cfg, charge):
    return request(cfg, "POST", "/api/v1/charges", charge)


def get_order(cfg, order_id):
    # quote(safe="") is the encodeURIComponent equivalent; order ids are alphanumeric anyway.
    return request(cfg, "GET", "/api/v1/orders/" + urllib.parse.quote(order_id, safe=""))


# verify_webhook checks X-Fluxa-Signature over "<timestamp>.<rawBody>". raw_body MUST be
# the exact received bytes — a re-serialized object will not match.
# Timestamp freshness is deliberately NOT checked here: that is a separate policy decision
# made by the receiver (see webhook.py), and keeping it out keeps this function pure.
def verify_webhook(webhook_secret, timestamp, raw_body, provided):
    signed_raw = _to_bytes(timestamp) + b"." + _to_bytes(raw_body)
    expected = sign(webhook_secret, signed_raw)
    # compare_digest is constant-time and handles length mismatches safely.
    return hmac.compare_digest(_to_bytes(expected), _to_bytes(provided))


# decrypt_webhook opens the AES-256-GCM envelope sent when the platform runs with
# WEBHOOK_ENCRYPTION=true. Key = SHA256(webhook_secret); blob = nonce[12] || ct || tag[16].
# Verify the signature BEFORE calling this — the signature covers the envelope.
#
# The stdlib has no AES, and hand-rolling one would be malpractice, so this single path
# needs `pip install cryptography`. Everything else in this demo stays zero-dependency.
def decrypt_webhook(webhook_secret, envelope_json):
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError(
            "Decrypting an encrypted envelope needs AES-256-GCM, which the Python standard "
            "library does not provide. Install it with: pip install cryptography "
            "(only needed when payload encryption is enabled; it is off by default)."
        )
    if isinstance(envelope_json, (str, bytes, bytearray)):
        env = json.loads(envelope_json)
    else:
        env = envelope_json
    key = hashlib.sha256(_to_bytes(webhook_secret)).digest()
    blob = base64.b64decode(env["data"])
    nonce = blob[:12]
    # AESGCM expects the 16-byte tag appended to the ciphertext, which is how Go writes it,
    # so blob[12:] goes in whole. aad is nil/None.
    ciphertext_and_tag = blob[12:]
    return AESGCM(key).decrypt(nonce, ciphertext_and_tag, None).decode("utf-8")
