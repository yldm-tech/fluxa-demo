// fluxa merchant API client: HMAC signing + charge + order lookup + webhook verification.
// Zero dependencies — only Node's built-in node:crypto / fetch.
//
// The signing scheme is specified in ../../spec/SIGNING.md and pinned by ../../spec/vectors.json.
import { createHmac, createHash, timingSafeEqual, createDecipheriv } from "node:crypto";

// canonicalQuery matches the server's canonical-query normalization (see
// ../../spec/SIGNING.md §1.1): split the raw query on "&", sort the fragments by UTF-8
// byte order, rejoin with "&". Empty query -> "".
// Sorting by bytes rather than JS's default UTF-16 code-unit order is what makes this
// agree with the server for every possible input, including raw code points above
// U+FFFF — the one range where the two orderings disagree.
function canonicalQuery(raw) {
  if (!raw) return "";
  return raw.split("&").sort(byteOrder).join("&");
}

function byteOrder(a, b) {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return Buffer.compare(ab, bb);
}

// canonical builds the 5-line string-to-sign. The third line is CANONICAL_QUERY and
// is an EMPTY LINE when there is no query — dropping it yields a 4-line string whose
// HMAC the server rejects as bad_signature.
export function canonical(method, path, rawQuery, timestamp, body) {
  const bodyHash = createHash("sha256").update(body ?? "", "utf8").digest("hex");
  return [method.toUpperCase(), path, canonicalQuery(rawQuery), timestamp, bodyHash].join("\n");
}

export function sign(secret, data) {
  return createHmac("sha256", secret).update(data, "utf8").digest("hex");
}

// signedHeaders computes the three auth headers. `path` may carry a query string;
// it is split and folded into the signature exactly as the server does.
export function signedHeaders(keyId, secret, method, path, body, nowSeconds) {
  const ts = String(nowSeconds ?? Math.floor(Date.now() / 1000));
  const qi = path.indexOf("?");
  const reqPath = qi >= 0 ? path.slice(0, qi) : path;
  const rawQuery = qi >= 0 ? path.slice(qi + 1) : "";
  return {
    "X-Api-Key": keyId,
    "X-Timestamp": ts,
    "X-Signature": sign(secret, canonical(method, reqPath, rawQuery, ts, body)),
  };
}

// request signs and sends one Merchant API call. The body is serialized ONCE and the
// exact same string is both signed and sent — re-serializing would change key order
// or spacing and invalidate the signature.
export async function request(cfg, method, path, payload) {
  const body = payload === undefined ? "" : JSON.stringify(payload);
  const headers = {
    ...signedHeaders(cfg.keyId, cfg.secret, method, path, body),
    "Content-Type": "application/json",
  };
  const res = await fetch(cfg.baseUrl + path, {
    method,
    headers,
    body: body === "" ? undefined : body,
  });
  const text = await res.text();
  let parsed;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`HTTP ${res.status}: response is not valid JSON: ${text.slice(0, 300)}`);
  }
  if (!res.ok) {
    const err = parsed?.error ?? parsed;
    throw new Error(`HTTP ${res.status} ${method} ${path}: ${JSON.stringify(err)}`);
  }
  return parsed;
}

export const createCharge = (cfg, charge) => request(cfg, "POST", "/api/v1/charges", charge);
export const getOrder = (cfg, orderId) =>
  request(cfg, "GET", `/api/v1/orders/${encodeURIComponent(orderId)}`);

// verifyWebhook checks X-Fluxa-Signature over "<timestamp>.<rawBody>". rawBody MUST be
// the exact received bytes — a re-serialized object will not match. It accepts either the
// received Buffer or a string: passing the Buffer hashes the received bytes verbatim, never
// round-tripping them through a String (which would turn invalid UTF-8 into replacement
// characters). A string rawBody hashes identically to before, so the vectors keep passing.
export function verifyWebhook(webhookSecret, timestamp, rawBody, provided) {
  const signedRaw = Buffer.isBuffer(rawBody)
    ? Buffer.concat([Buffer.from(`${timestamp}.`, "utf8"), rawBody])
    : `${timestamp}.${rawBody}`;
  const expected = sign(webhookSecret, signedRaw);
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(provided ?? "", "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

// decryptWebhook opens the AES-256-GCM envelope sent when the platform runs with
// WEBHOOK_ENCRYPTION=true. Key = SHA256(webhook_secret); blob = nonce[12] || ct || tag[16].
// Verify the signature BEFORE calling this — the signature covers the envelope.
export function decryptWebhook(webhookSecret, envelopeJson) {
  const env = typeof envelopeJson === "string" ? JSON.parse(envelopeJson) : envelopeJson;
  const key = createHash("sha256").update(webhookSecret, "utf8").digest();
  const blob = Buffer.from(env.data, "base64");
  const nonce = blob.subarray(0, 12);
  const tag = blob.subarray(blob.length - 16);
  const ciphertext = blob.subarray(12, blob.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
