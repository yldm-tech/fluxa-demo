# Known-answer tests: this implementation must reproduce ../../spec/vectors.json byte for
# byte. Those vectors are generated from fluxa's actual server-side signing code, which
# makes them the criterion for a correct port — no running server required.
#
#   python3 -m unittest discover
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from fluxa import (  # noqa: E402
    HAS_CRYPTOGRAPHY,
    canonical,
    decrypt_webhook,
    sign,
    signed_headers,
    verify_webhook,
)

_SPEC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "spec", "vectors.json")
with open(_SPEC, "r", encoding="utf-8") as f:
    vectors = json.load(f)


class RequestVectors(unittest.TestCase):
    def test_request_vectors(self):
        """Request signing vectors."""
        self.assertTrue(vectors["requests"], "the vectors file has no requests")
        for v in vectors["requests"]:
            with self.subTest(name=v["name"]):
                canon = canonical(v["method"], v["path"], v["raw_query"], v["timestamp"], v["body"])
                self.assertEqual(canon, v["canonical"], "canonical string does not match")
                self.assertEqual(sign(v["secret"], canon), v["signature"], "signature does not match")

    def test_no_query_canonical_has_empty_third_line(self):
        """With no query the canonical's 3rd line must be empty (5 lines, not 4)."""
        canon = canonical("POST", "/api/v1/charges", "", "1750000000", "{}")
        lines = canon.split("\n")
        self.assertEqual(len(lines), 5, "canonical must be 5 lines")
        self.assertEqual(lines[2], "", "line 3 (CANONICAL_QUERY) must be the empty string")

    def test_query_order_irrelevant_but_tampering_is_not(self):
        """Query order does not change the signature, but tampering does."""
        a = canonical("GET", "/api/v1/orders", "status=paid&limit=10", "1750000000", "")
        b = canonical("GET", "/api/v1/orders", "limit=10&status=paid", "1750000000", "")
        self.assertEqual(a, b, "a different parameter order must yield the same canonical")
        tampered = canonical("GET", "/api/v1/orders", "status=failed&limit=10", "1750000000", "")
        self.assertNotEqual(a, tampered, "tampering with a parameter value must change the canonical")
        dropped = canonical("GET", "/api/v1/orders", "", "1750000000", "")
        self.assertNotEqual(a, dropped, "dropping the query must change the canonical")

    def test_signed_headers_folds_query_from_path(self):
        """signed_headers folds a query from the path into the signature."""
        h = signed_headers(
            "pk_x", "sk_x", "GET", "/api/v1/orders?status=paid&limit=10", "", 1750000000
        )
        want = sign(
            "sk_x", canonical("GET", "/api/v1/orders", "status=paid&limit=10", "1750000000", "")
        )
        self.assertEqual(h["X-Signature"], want)
        self.assertEqual(h["X-Timestamp"], "1750000000")
        self.assertEqual(h["X-Api-Key"], "pk_x")


class WebhookVectors(unittest.TestCase):
    def test_webhook_vectors(self):
        """Webhook signature vectors."""
        self.assertTrue(vectors["webhooks"], "the vectors file has no webhooks")
        for w in vectors["webhooks"]:
            with self.subTest(name=w["name"]):
                self.assertEqual(sign(w["secret"], w["signed_raw"]), w["signature"])
                self.assertTrue(
                    verify_webhook(w["secret"], w["timestamp"], w["body"], w["signature"]),
                    "should verify",
                )
                self.assertFalse(
                    verify_webhook(w["secret"], w["timestamp"], w["body"] + "x", w["signature"]),
                    "a tampered body must be rejected",
                )
                self.assertFalse(
                    verify_webhook("wrong_secret", w["timestamp"], w["body"], w["signature"]),
                    "a wrong secret must be rejected",
                )
                self.assertFalse(
                    verify_webhook(w["secret"], w["timestamp"], w["body"], ""), "an empty signature must be rejected"
                )

    def test_verify_accepts_raw_bytes(self):
        """Raw bytes and the equivalent str verify identically (the receiver gets bytes)."""
        w = vectors["webhooks"][0]
        self.assertTrue(
            verify_webhook(w["secret"], w["timestamp"], w["body"].encode("utf-8"), w["signature"])
        )


class EnvelopeVectors(unittest.TestCase):
    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "decrypting the AES-256-GCM envelope needs cryptography")
    def test_envelope_vectors(self):
        """AES-256-GCM envelope decryption vectors."""
        self.assertTrue(vectors["envelopes"], "the vectors file has no envelopes")
        for e in vectors["envelopes"]:
            with self.subTest(name=e["name"]):
                self.assertEqual(decrypt_webhook(e["secret"], e["envelope"]), e["plaintext"])
                with self.assertRaises(Exception, msg="a wrong secret must fail to decrypt"):
                    decrypt_webhook("wrong_secret", e["envelope"])

    @unittest.skipIf(HAS_CRYPTOGRAPHY, "cryptography is installed, so the missing-dependency branch does not apply")
    def test_missing_cryptography_error_is_actionable(self):
        """Without cryptography installed, the error must tell the user exactly what to do."""
        e = vectors["envelopes"][0]
        with self.assertRaises(RuntimeError) as ctx:
            decrypt_webhook(e["secret"], e["envelope"])
        self.assertIn("pip install cryptography", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
