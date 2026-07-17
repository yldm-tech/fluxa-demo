# Known-answer tests: this implementation must reproduce ../../spec/vectors.json byte for
# byte. Those vectors are generated from fluxa's actual server-side signing code, which makes
# them the criterion for a correct port — no running server required.
#
#   ruby test/vectors_test.rb
#
# Besides the vectors, this file carries two groups of webhook regression tests (see the
# "idempotency key regression" and "refund ordering regression" groups). Those check no
# vectors, but this demo has a single test entrypoint, so they live here to be picked up by
# ./verify-all.sh ruby too.
#
# Hand-rolled assertions on purpose: minitest is a bundled *gem*, and this demo commits to
# standard library only, on both Ruby 2.6 and 3.x. Exits non-zero if anything fails.
require "json"
require "bigdecimal"
require_relative "../lib/fluxa"

VECTORS = JSON.parse(File.read(File.join(__dir__, "..", "..", "spec", "vectors.json")))

$failed = 0
$passed = 0
$skipped = 0

def test(name)
  yield
  $passed += 1
  puts "  \e[32m✓\e[0m #{name}"
rescue StandardError => e
  $failed += 1
  puts "  \e[31m✗ #{name}\e[0m"
  puts e.message.to_s.split("\n").map { |l| "      #{l}" }.join("\n")
end

def skip(name, reason)
  $skipped += 1
  puts "  \e[33m- #{name} (SKIPPED)\e[0m"
  puts reason.split("\n").map { |l| "      #{l}" }.join("\n")
end

# macOS's system ruby (2.6) links LibreSSL rather than OpenSSL, and LibreSSL cannot do
# AES-GCM at all — even encrypting one block raises CipherError — so this probes the
# interpreter rather than the code under test. The very same lib/fluxa.rb decrypts the
# envelope vector on any OpenSSL-linked Ruby (verified on 2.6 + OpenSSL 1.1.1n, 3.3 +
# OpenSSL 3.2.4, 4.0 + OpenSSL 3.6.2), so this is a LibreSSL issue, not a Ruby-version one.
def gcm_available?
  c = OpenSSL::Cipher.new("aes-256-gcm")
  c.encrypt
  c.key = "k" * 32
  c.iv = "n" * 12
  c.update("probe") + c.final
  true
rescue OpenSSL::Cipher::CipherError
  false
end

def group(name)
  puts "\n#{name}"
  yield
end

class AssertionError < StandardError; end

def assert_equal(want, got, msg)
  return if want == got

  raise AssertionError, "#{msg}\nwant: #{want.inspect}\ngot:  #{got.inspect}"
end

def assert_not_equal(unwanted, got, msg)
  return unless unwanted == got

  raise AssertionError, "#{msg}\nboth were: #{got.inspect}"
end

def assert(cond, msg)
  raise AssertionError, msg unless cond
end

def assert_raises(msg)
  yield
  raise AssertionError, msg
rescue AssertionError
  raise
rescue StandardError
  nil # expected
end

group("request signing vectors") do
  VECTORS["requests"].each do |v|
    test(v["name"]) do
      canon = Fluxa.canonical(v["method"], v["path"], v["raw_query"], v["timestamp"], v["body"])
      assert_equal(v["canonical"], canon, "canonical string does not match")
      assert_equal(v["signature"], Fluxa.sign(v["secret"], canon), "signature does not match")
    end
  end
end

group("canonical structure") do
  test("with no query the 3rd line must be empty (5 lines, not 4)") do
    canon = Fluxa.canonical("POST", "/api/v1/charges", "", "1750000000", "{}")
    lines = canon.split("\n", -1)
    assert_equal(5, lines.length, "canonical must be 5 lines")
    assert_equal("", lines[2], "line 3 (CANONICAL_QUERY) must be the empty string")
  end

  test("query order does not change the signature, but tampering does") do
    a = Fluxa.canonical("GET", "/api/v1/orders", "status=paid&limit=10", "1750000000", "")
    b = Fluxa.canonical("GET", "/api/v1/orders", "limit=10&status=paid", "1750000000", "")
    assert_equal(a, b, "a different parameter order must yield the same canonical")
    assert_equal(Fluxa.sign("sk_x", a), Fluxa.sign("sk_x", b), "a different parameter order must yield the same signature")

    tampered = Fluxa.canonical("GET", "/api/v1/orders", "status=failed&limit=10", "1750000000", "")
    assert_not_equal(a, tampered, "tampering with a parameter value must change the canonical")
    dropped = Fluxa.canonical("GET", "/api/v1/orders", "", "1750000000", "")
    assert_not_equal(a, dropped, "dropping the query must change the canonical")
  end

  # Ruby's String#<=> is a byte comparison; this pins it at the one boundary where a UTF-16
  # code-unit sort would disagree with the server's UTF-8 byte order.
  test("query fragments sort in UTF-8 byte order (U+FFFF before U+10000)") do
    assert_equal("a=\u{FFFF}&b=\u{10000}",
                 Fluxa.canonical_query("b=\u{10000}&a=\u{FFFF}"),
                 "must sort by UTF-8 byte order, not UTF-16 code-unit order")
  end

  test("signed_headers folds a query from the path into the signature") do
    h = Fluxa.signed_headers("pk_x", "sk_x", "GET", "/api/v1/orders?status=paid&limit=10", "",
                             1_750_000_000)
    want = Fluxa.sign("sk_x",
                      Fluxa.canonical("GET", "/api/v1/orders", "status=paid&limit=10",
                                      "1750000000", ""))
    assert_equal(want, h["X-Signature"], "X-Signature must cover the query")
    assert_equal("1750000000", h["X-Timestamp"], "X-Timestamp does not match")
    assert_equal("pk_x", h["X-Api-Key"], "X-Api-Key does not match")
  end
end

group("webhook signature vectors") do
  VECTORS["webhooks"].each do |w|
    test(w["name"]) do
      assert_equal(w["signature"], Fluxa.sign(w["secret"], w["signed_raw"]), "signature does not match")
      assert(Fluxa.verify_webhook(w["secret"], w["timestamp"], w["body"], w["signature"]),
             "should verify")
      assert(!Fluxa.verify_webhook(w["secret"], w["timestamp"], "#{w['body']}x", w["signature"]),
             "a tampered body must be rejected")
      assert(!Fluxa.verify_webhook("wrong_secret", w["timestamp"], w["body"], w["signature"]),
             "a wrong secret must be rejected")
      assert(!Fluxa.verify_webhook(w["secret"], w["timestamp"], w["body"], ""), "an empty signature must be rejected")
      assert(!Fluxa.verify_webhook(w["secret"], "1750000001", w["body"], w["signature"]),
             "a tampered timestamp must be rejected")
    end
  end

  # The socket hands the receiver ASCII-8BIT bytes; signing must not blow up on non-ASCII.
  test("verification does not raise an encoding error when the raw body is binary") do
    secret = "sk_test_demo_secret_do_not_use_in_prod"
    body = '{"subject":"咖啡 ☕"}'
    sig = Fluxa.sign(secret, Fluxa.webhook_signing_input("1750000000", body))
    assert(Fluxa.verify_webhook(secret, "1750000000", body.dup.force_encoding("ASCII-8BIT"), sig),
           "a binary body must produce the same signature as a UTF-8 body")
  end
end

# Idempotency-key regression tests.
#
# fluxa allows an order to be partially refunded repeatedly — further refunds are accepted
# until refunded_amount reaches the order total — and every one of them fires its own
# payment.refunded event. So (event, order_id) is NOT unique.
#
# Deduplicating on (event, order_id) alone silently drops the second partial refund and
# answers 2xx: fluxa treats the delivery as successful and never retries, the customer is
# under-refunded, and nothing errors anywhere in the chain. This group pins the correct
# behavior. See ../../spec/SIGNING.md §3.1.

# Kept in sync with dedupe_key in lib/webhook.rb. Redefined here rather than required:
# loading lib/webhook.rb starts a TCPServer and begins accepting, and a test must not turn
# itself into a server.
def dedupe_key(evt)
  "#{evt['event']}:#{evt['order_id']}:#{evt['refunded_amount']}"
end

# The broken implementation these tests falsify — kept here so nobody "simplifies" back to it.
def broken_key(evt)
  "#{evt['event']}:#{evt['order_id']}"
end

def refund(cumulative, status = "partially_refunded")
  {
    "event" => "payment.refunded",
    "order_id" => "ord_X",
    "merchant_order_id" => "o-1",
    "amount" => "1000.00",
    "refunded_amount" => cumulative,
    "currency" => "USD",
    "status" => status,
    "channel" => "mock",
  }
end

group("idempotency key regression") do
  test("two partial refunds must have different idempotency keys") do
    first = refund("30.00")
    second = refund("50.00") # cumulative: 30 + 20
    assert_not_equal(dedupe_key(first), dedupe_key(second),
                     "two partial refunds collapsed into one event — the second would be dropped")

    # Documents the bug that was fixed: the old key collapses both refunds into one.
    assert_equal(broken_key(first), broken_key(second),
                 "premise check: the old (event, order_id) key really does collide")
  end

  test("a redelivery of the same event must hit the same idempotency key") do
    evt = refund("30.00")
    assert_equal(dedupe_key(evt), dedupe_key(evt.dup), "a redelivery must be deduplicated")
  end

  test("a full refund differs from an earlier partial refund") do
    assert_not_equal(dedupe_key(refund("30.00")), dedupe_key(refund("1000.00", "refunded")),
                     "a full refund must be distinguishable from an earlier partial refund")
  end

  test("payment.succeeded has no refunded_amount, so the key degrades to (event, order_id)") do
    ok = { "event" => "payment.succeeded", "order_id" => "ord_X", "status" => "paid" }
    assert_equal("payment.succeeded:ord_X:", dedupe_key(ok), "a missing field must interpolate to an empty string")
    assert_equal(dedupe_key(ok), dedupe_key(ok.dup), "a redelivery must be deduplicated")
  end

  test("succeeded and refunded are different keys") do
    ok = { "event" => "payment.succeeded", "order_id" => "ord_X" }
    assert_not_equal(dedupe_key(ok), dedupe_key(refund("30.00")), "different events must have different keys")
  end

  # The real-world scenario: refund 30 then 20 against a 1000 order (cumulative 50).
  test("end to end: both partial refunds against a 1000 order must be processed") do
    processed = {}
    accept = lambda do |evt|
      k = dedupe_key(evt)
      next false if processed.key?(k)

      processed[k] = true
      true
    end

    assert_equal(true, accept.call(refund("30.00")), "the first refund should be processed")
    assert_equal(false, accept.call(refund("30.00")), "a redelivery of the first must be deduplicated")
    assert_equal(true, accept.call(refund("50.00")), "the second partial refund must be processed — this is exactly the one the old logic dropped")
    assert_equal(false, accept.call(refund("50.00")), "a redelivery of the second must be deduplicated")
  end
end

# Ordering regression tests.
#
# at-least-once says nothing about ORDER. Deliveries are not serialized per order, and a
# failed delivery is retried after a backoff — so the event carrying the 30 can land after
# the one carrying 50.
#
# Dedupe alone does not save you here: a late 30 is a DIFFERENT key from 50, so it is
# correctly not a duplicate — it gets processed, and a blind assignment regresses the
# recorded total. Advancing to max(recorded, incoming) is idempotent AND order-safe.
# See ../../spec/SIGNING.md §3.1.

# Cumulative totals are decimal strings. Comparing them as floats is the very bug the rest
# of this repo warns about, and comparing them as strings is wrong too, so parse them with
# BigDecimal — exact, and in the standard library. The recorded value stays a string:
# BigDecimal is for the comparison only.
def advance(recorded, incoming)
  BigDecimal(incoming) > BigDecimal(recorded) ? incoming : recorded
end

group("refund ordering regression") do
  test("out-of-order refunds must not regress the recorded total") do
    recorded = "0"

    # The 50 lands first (the 30's delivery failed and is still backing off).
    recorded = advance(recorded, refund("50.00")["refunded_amount"])
    assert_equal("50.00", recorded, "the first refund to arrive should be recorded")

    # The 30 arrives late on retry. It is NOT a duplicate — different key — so it is
    # processed. A blind assignment would drop the total back to 30.
    recorded = advance(recorded, refund("30.00")["refunded_amount"])
    assert_equal("50.00", recorded, "a late, lower cumulative value must not move the total backwards")
  end

  test("in-order refunds still advance normally") do
    recorded = "0"
    recorded = advance(recorded, "30.00")
    assert_equal("30.00", recorded, "the first partial refund must be recorded")
    recorded = advance(recorded, "50.00")
    assert_equal("50.00", recorded, "the second partial refund must advance the total")
    recorded = advance(recorded, "1000.00") # fully refunded
    assert_equal("1000.00", recorded, "a full refund must advance the total")
  end

  test("a redelivery of the same cumulative value is a no-op") do
    assert_equal("50.00", advance("50.00", "50.00"), "a redelivery must not move the total")
  end

  test("the comparison is a decimal one, not a float or string one") do
    assert_equal("50.00", advance("30.00", "50.00"), "a higher cumulative value must advance the total")
    assert_equal("50.00", advance("50.00", "30.00"), "a lower cumulative value must be ignored")

    # Naive string compare gets this wrong: "9.90" > "10.00" lexicographically.
    assert_equal("10.00", advance("9.90", "10.00"), "10.00 must be greater than 9.90")
    assert_equal("10.00", advance("10.00", "9.90"), "10.00 must be greater than 9.90")

    # Premise check: the naive string compare these tests falsify really is wrong.
    assert("9.90" > "10.00", "premise check: lexicographically 9.90 really does sort above 10.00")
    assert(BigDecimal("10.00") > BigDecimal("9.90"), "as decimals the order is the arithmetic one")
  end
end

group("AES-256-GCM envelope decryption vectors") do
  VECTORS["envelopes"].each do |e|
    unless gcm_available?
      skip(e["name"],
           "This Ruby (#{RUBY_VERSION}) links #{OpenSSL::OPENSSL_VERSION}, which cannot do AES-GCM at all\n" \
           "(even encrypting fails). That is an interpreter limitation, not a problem with this\n" \
           "implementation — the same code passes fully on any OpenSSL-linked Ruby:\n" \
           "  /opt/homebrew/opt/ruby/bin/ruby test/vectors_test.rb\n" \
           "  docker run --rm -v \"$PWD/..\":/app -w /app/ruby ruby:3.3-slim ruby test/vectors_test.rb\n" \
           "Signing, charging, and plaintext webhook verification all work here; only the\n" \
           "encrypted envelope needs OpenSSL.")
      next
    end

    test(e["name"]) do
      assert_equal(e["plaintext"], Fluxa.decrypt_webhook(e["secret"], e["envelope"]), "decrypted plaintext does not match")
      assert_raises("a wrong secret must fail to decrypt") { Fluxa.decrypt_webhook("wrong_secret", e["envelope"]) }

      # Flip one ciphertext byte: the GCM tag must reject it.
      env = JSON.parse(e["envelope"])
      blob = env["data"].unpack1("m0")
      blob.setbyte(20, blob.getbyte(20) ^ 0x01)
      env["data"] = [blob].pack("m0")
      assert_raises("a tampered ciphertext must fail to decrypt") { Fluxa.decrypt_webhook(e["secret"], JSON.generate(env)) }
    end
  end

  # When running on LibreSSL, at least verify that the guard gives an actionable message
  # rather than an empty-message CipherError.
  unless gcm_available?
    test("on LibreSSL, decrypt_webhook raises an actionable error") do
      e = VECTORS["envelopes"][0]
      begin
        Fluxa.decrypt_webhook(e["secret"], e["envelope"])
        raise AssertionError, "GCM is unavailable here, so decrypt_webhook should raise GcmUnavailableError"
      rescue Fluxa::GcmUnavailableError => err
        assert(err.message.include?("OpenSSL"), "the error message should tell the user to switch to an OpenSSL-linked Ruby")
        assert(err.message.include?("LibreSSL"), "the error message should point out that this Ruby links LibreSSL")
      end
    end
  end
end

summary = "\n#{$passed} passed"
summary += ", \e[33m#{$skipped} skipped\e[0m" if $skipped.positive?
summary += ", #{$failed} failed"
puts "#{summary}  (ruby #{RUBY_VERSION}, #{OpenSSL::OPENSSL_VERSION})"
exit($failed.zero? ? 0 : 1)
