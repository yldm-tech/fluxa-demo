// Known-answer tests: this implementation must reproduce ../../spec/vectors.json byte for
// byte. Those vectors are generated from fluxa's actual server-side signing code, which
// makes them the criterion for a correct port — no running server required.
//
//   node --test test/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { canonical, sign, verifyWebhook, decryptWebhook, signedHeaders } from "../src/fluxa.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "..", "..", "spec", "vectors.json"), "utf8"));

test("request signing vectors", async (t) => {
  for (const v of vectors.requests) {
    await t.test(v.name, () => {
      const canon = canonical(v.method, v.path, v.raw_query, v.timestamp, v.body);
      assert.equal(canon, v.canonical, "canonical string does not match");
      assert.equal(sign(v.secret, canon), v.signature, "signature does not match");
    });
  }
});

test("with no query the canonical's 3rd line must be empty (5 lines, not 4)", () => {
  const canon = canonical("POST", "/api/v1/charges", "", "1750000000", "{}");
  const lines = canon.split("\n");
  assert.equal(lines.length, 5, "canonical must be 5 lines");
  assert.equal(lines[2], "", "line 3 (CANONICAL_QUERY) must be the empty string");
});

test("query order does not change the signature, but tampering does", () => {
  const a = canonical("GET", "/api/v1/orders", "status=paid&limit=10", "1750000000", "");
  const b = canonical("GET", "/api/v1/orders", "limit=10&status=paid", "1750000000", "");
  assert.equal(a, b, "a different parameter order must yield the same canonical");
  const tampered = canonical("GET", "/api/v1/orders", "status=failed&limit=10", "1750000000", "");
  assert.notEqual(a, tampered, "tampering with a parameter value must change the canonical");
  const dropped = canonical("GET", "/api/v1/orders", "", "1750000000", "");
  assert.notEqual(a, dropped, "dropping the query must change the canonical");
});

test("signedHeaders folds a query from the path into the signature", () => {
  const h = signedHeaders("pk_x", "sk_x", "GET", "/api/v1/orders?status=paid&limit=10", "", 1750000000);
  const want = sign("sk_x", canonical("GET", "/api/v1/orders", "status=paid&limit=10", "1750000000", ""));
  assert.equal(h["X-Signature"], want);
  assert.equal(h["X-Timestamp"], "1750000000");
  assert.equal(h["X-Api-Key"], "pk_x");
});

test("webhook signature vectors", async (t) => {
  for (const w of vectors.webhooks) {
    await t.test(w.name, () => {
      assert.equal(sign(w.secret, w.signed_raw), w.signature);
      assert.ok(verifyWebhook(w.secret, w.timestamp, w.body, w.signature), "should verify");
      assert.ok(!verifyWebhook(w.secret, w.timestamp, w.body + "x", w.signature), "a tampered body must be rejected");
      assert.ok(!verifyWebhook("wrong_secret", w.timestamp, w.body, w.signature), "a wrong secret must be rejected");
      assert.ok(!verifyWebhook(w.secret, w.timestamp, w.body, ""), "an empty signature must be rejected");
    });
  }
});

test("AES-256-GCM envelope decryption vectors", async (t) => {
  for (const e of vectors.envelopes) {
    await t.test(e.name, () => {
      assert.equal(decryptWebhook(e.secret, e.envelope), e.plaintext);
      assert.throws(() => decryptWebhook("wrong_secret", e.envelope), "a wrong secret must fail to decrypt");
    });
  }
});
