# Webhook receiver demo: verify signature -> decrypt (if enabled) -> process idempotently -> 2xx.
#   python3 src/webhook.py
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from config import config
from fluxa import decrypt_webhook, verify_webhook

# Delivery is at-least-once: the same event can arrive more than once, so processing must
# be idempotent.
#
# The idempotency key MUST include refunded_amount — (event, order_id) alone is NOT unique:
# a single order can be partially refunded multiple times, and each refund fires its own
# payment.refunded. Deduplicating on just (event, order_id) makes the second partial refund
# look like a duplicate delivery: it gets dropped and answered with a 2xx, so fluxa records
# the delivery as successful and never retries. The customer is under-refunded and nothing
# errors anywhere in the chain.
# refunded_amount is a cumulative total and strictly increasing, so it separates a
# redelivery of the same event (same value -> deduplicate) from a genuinely new partial
# refund (higher value -> process).
#
# In a real integration this belongs in the database as a unique index on
# (order_id, event, refunded_amount); the in-process set here is demo-only.
processed = set()


# dedupe_key, per the note above: payment.succeeded / failed carry no refunded_amount, so
# the key degrades to (event, order_id).
def dedupe_key(evt):
    refunded = evt.get("refunded_amount")
    return "{}:{}:{}".format(
        evt.get("event"), evt.get("order_id"), "" if refunded is None else refunded
    )


MAX_SKEW_SECONDS = 300
MAX_BODY_BYTES = 1 << 20


class WebhookHandler(BaseHTTPRequestHandler):
    def _reply(self, code, text):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Silence the default access log; this demo prints its own, clearer lines.
        pass

    def do_GET(self):
        self._reply(405, "only POST")

    def do_POST(self):
        # Parse Content-Length defensively: this runs before any signature check, so an
        # unauthenticated caller controls the header. A non-numeric or negative value must
        # be a clean 400, not an uncaught ValueError — BaseHTTPRequestHandler would turn
        # that into a traceback and a dropped connection with no HTTP response at all.
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._reply(400, "invalid Content-Length")
            return
        if length < 0:
            self._reply(400, "invalid Content-Length")
            return
        if length > MAX_BODY_BYTES:
            self._reply(413, "body too large")
            return

        # The signature must be verified against the raw bytes: deserializing and
        # re-serializing changes them, and the signature will no longer match.
        raw_body = self.rfile.read(length)
        event = self.headers.get("X-Fluxa-Event")
        ts = self.headers.get("X-Fluxa-Timestamp")
        sig = self.headers.get("X-Fluxa-Signature")
        encryption = self.headers.get("X-Fluxa-Encryption")

        if not verify_webhook(config.webhook_secret, ts, raw_body, sig):
            print("✗ Signature verification failed event={} — rejected".format(event))
            self._reply(401, "bad signature")
            return

        # Check the timestamp only after the signature passes, to limit the replay window.
        try:
            skew = abs(int(time.time()) - int(ts))
        except (TypeError, ValueError):
            skew = None
        if skew is None or skew > MAX_SKEW_SECONDS:
            print("✗ Timestamp outside the allowed window ({}s) event={} — rejected".format(skew, event))
            self._reply(401, "stale timestamp")
            return

        # Verify first, then decrypt: the signature covers the envelope as it was sent.
        payload = raw_body
        if encryption == "A256GCM":
            try:
                payload = decrypt_webhook(config.webhook_secret, raw_body)
                print("  (payload was an AES-256-GCM encrypted envelope — decrypted)")
            except Exception as e:
                print("✗ Decryption failed: {}".format(e))
                self._reply(400, "bad envelope")
                return

        try:
            evt = json.loads(payload)
        except ValueError:
            self._reply(400, "bad json")
            return

        key = dedupe_key(evt)
        if key in processed:
            # Duplicate delivery: already handled, so return 2xx without shipping or
            # crediting anything a second time.
            print("↺ Duplicate delivery ignored {}".format(key))
            self._reply(200, "ok (duplicate)")
            return
        processed.add(key)

        print(
            "✓ {}  order={}  merchant_order={}".format(
                evt.get("event"), evt.get("order_id"), evt.get("merchant_order_id")
            )
        )
        print(
            "  {} {}  status={}  channel={}".format(
                evt.get("amount"), evt.get("currency"), evt.get("status"), evt.get("channel")
            )
        )

        if evt.get("is_test"):
            # Orders made with a test key do fire real webhooks (that is how you exercise
            # the integration), but no real money moved.
            print("  ⚠ is_test=true: this is a test order — do not ship anything.")

        if evt.get("event") == "payment.succeeded":
            if not evt.get("is_test"):
                print("  → Ship goods / grant entitlements here (treat amounts as decimal strings, never floats)")
        elif evt.get("event") == "payment.failed":
            print("  → Mark the order failed here")
        elif evt.get("event") == "payment.refunded":
            # refunded_amount is the CUMULATIVE refunded total, not the amount of this
            # refund; evt["amount"] is the ORDER TOTAL. Computing a refund from it would
            # read "1 refunded on a 1000 order" as "1000 refunded".
            #
            # Move your recorded total FORWARD ONLY — never add, and never assign blindly.
            # Delivery is at-least-once and arrival order is not guaranteed: deliveries are
            # not serialized per order, and a failed one is retried after a backoff, so the
            # event carrying 30 can land AFTER the one carrying 50. The late 30 is not a
            # duplicate (different key, correctly processed), so assigning would regress the
            # total from 50 back to 30 and under-refund the customer; adding would
            # over-refund on a redelivery. max() is idempotent AND order-safe.
            # Compare as decimals, not floats or strings ("9.90" > "10.00" lexicographically).
            # See ../../spec/SIGNING.md §3.1.
            refunded = evt.get("refunded_amount")
            print(
                "  → Refunded so far {} of order total {} {} (status={}; partially_refunded means more may follow)".format(
                    "0" if refunded is None else refunded,
                    evt.get("amount"),
                    evt.get("currency"),
                    evt.get("status"),
                )
            )
            print(
                "  → Advance your recorded refunded total to max(recorded, refunded_amount)"
                " — never assign blindly, and never add"
            )

        # Return 2xx quickly; anything else is retried by fluxa with exponential backoff
        # (up to 8 attempts).
        self._reply(200, "ok")


def main():
    # Long-running server: line-buffer stdout so `python3 src/webhook.py | tee run.log`
    # (or Docker) shows each event as it arrives instead of stalling in a block buffer.
    sys.stdout.reconfigure(line_buffering=True)

    # Validate the webhook secret at startup rather than failing on the first callback that
    # arrives — the property exits with an actionable message if it is unset.
    _ = config.webhook_secret

    # Single-threaded on purpose: mirrors the Node demo's model and keeps the `processed`
    # dedupe set race-free without a lock.
    server = HTTPServer(("", config.webhook_port), WebhookHandler)
    print("fluxa webhook receiver listening on http://localhost:{}".format(config.webhook_port))
    print("Point your portal callback URL here (it must be publicly reachable — use a tunnel such as ngrok for local testing).")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
