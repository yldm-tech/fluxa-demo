# Webhook receiver demo: verify signature -> decrypt (if enabled) -> process idempotently -> 2xx.
#   ruby lib/webhook.rb
#
# A minimal HTTP server hand-rolled on the stdlib's TCPServer rather than webrick: webrick
# stopped being a default gem in Ruby 3.0, so using it would mean taking a dependency. This
# demo commits to zero gems.
require "socket"
require "json"
require_relative "fluxa"
require_relative "config"

# Log in real time: stdout is block-buffered when piped or redirected, so without this you
# would not see events as they arrive.
STDOUT.sync = true

config = Fluxa::Config.default

# Delivery is at-least-once: the same event can arrive more than once, so processing must be
# idempotent.
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
# (order_id, event, refunded_amount); the in-process hash here is demo-only.
processed = {}
lock = Mutex.new

MAX_SKEW_SECONDS = 300
MAX_BODY_BYTES = 1 << 20

def respond(sock, status, text)
  body = text.b
  sock.write("HTTP/1.1 #{status}\r\n" \
             "Content-Type: text/plain; charset=utf-8\r\n" \
             "Content-Length: #{body.bytesize}\r\n" \
             "Connection: close\r\n\r\n")
  sock.write(body)
end

# Minimal HTTP parse: request line, headers until the blank line, then exactly
# Content-Length bytes. The body is read in binary — verifying against re-encoded text
# would change the bytes and break the signature.
def read_request(sock)
  request_line = sock.gets
  return nil if request_line.nil?

  method = request_line.split(" ")[0].to_s.upcase
  headers = {}
  while (line = sock.gets)
    line = line.chomp
    break if line.empty?

    k, v = line.split(":", 2)
    headers[k.to_s.strip.downcase] = v.to_s.strip
  end

  length = headers["content-length"].to_i
  return [method, headers, :too_large] if length > MAX_BODY_BYTES

  body = length.positive? ? sock.read(length).to_s.b : "".b
  [method, headers, body]
end

# dedupe_key, per the note above: payment.succeeded / failed carry no refunded_amount, and
# nil interpolates to an empty string, so the key degrades to (event, order_id).
def dedupe_key(evt)
  "#{evt['event']}:#{evt['order_id']}:#{evt['refunded_amount']}"
end

def handle(sock, config, processed, lock)
  method, headers, raw_body = read_request(sock)
  return if method.nil?

  unless method == "POST"
    respond(sock, "405 Method Not Allowed", "only POST")
    return
  end
  if raw_body == :too_large
    respond(sock, "413 Payload Too Large", "body too large")
    return
  end

  event = headers["x-fluxa-event"]
  ts = headers["x-fluxa-timestamp"]
  sig = headers["x-fluxa-signature"]
  encryption = headers["x-fluxa-encryption"]

  # The signature must be verified against the raw bytes: deserializing and re-serializing
  # changes them, and the signature will no longer match.
  unless Fluxa.verify_webhook(config.webhook_secret, ts, raw_body, sig)
    warn "✗ Signature verification failed event=#{event} — rejected"
    respond(sock, "401 Unauthorized", "bad signature")
    return
  end

  # Check the timestamp only after the signature passes, to limit the replay window.
  skew = (Time.now.to_i - ts.to_i).abs
  if ts.nil? || ts.empty? || skew > MAX_SKEW_SECONDS
    warn "✗ Timestamp outside the allowed window (#{skew}s) event=#{event} — rejected"
    respond(sock, "401 Unauthorized", "stale timestamp")
    return
  end

  # Verify first, then decrypt: the signature covers the envelope as it was sent.
  payload = raw_body
  if encryption == "A256GCM"
    begin
      payload = Fluxa.decrypt_webhook(config.webhook_secret, raw_body)
      puts "  (payload was an AES-256-GCM encrypted envelope — decrypted)"
    rescue Fluxa::GcmUnavailableError => e
      # This Ruby cannot do AES-GCM. The exception message already carries actionable
      # instructions, so print it verbatim.
      warn "✗ Cannot decrypt the encrypted webhook:\n#{e.message}"
      respond(sock, "500 Internal Server Error", "gcm unavailable")
      return
    rescue OpenSSL::Cipher::CipherError, ArgumentError, JSON::ParserError => e
      warn "✗ Decryption failed: #{e.class}: #{e.message}"
      respond(sock, "400 Bad Request", "bad envelope")
      return
    end
  end

  begin
    evt = JSON.parse(payload)
  rescue JSON::ParserError
    respond(sock, "400 Bad Request", "bad json")
    return
  end

  key = dedupe_key(evt)
  duplicate = lock.synchronize do
    processed.key?(key) ? true : (processed[key] = true) && false
  end
  if duplicate
    # Duplicate delivery: already handled, so return 2xx without shipping or crediting
    # anything a second time.
    puts "↺ Duplicate delivery ignored #{key}"
    respond(sock, "200 OK", "ok (duplicate)")
    return
  end

  puts "✓ #{evt['event']}  order=#{evt['order_id']}  merchant_order=#{evt['merchant_order_id']}"
  puts "  #{evt['amount']} #{evt['currency']}  status=#{evt['status']}  channel=#{evt['channel']}"

  if evt["is_test"]
    # Orders made with a test key do fire real webhooks (that is how you exercise the
    # integration), but no real money moved.
    puts "  ⚠ is_test=true: this is a test order — do not ship anything."
  end

  case evt["event"]
  when "payment.succeeded"
    unless evt["is_test"]
      puts "  → Ship goods / grant entitlements here (treat amounts as decimal strings, never floats)"
    end
  when "payment.failed"
    puts "  → Mark the order failed here"
  when "payment.refunded"
    # refunded_amount is the CUMULATIVE refunded total, not the amount of this refund;
    # evt['amount'] is the ORDER TOTAL. Computing a refund from it would read "1 refunded on
    # a 1000 order" as "1000 refunded".
    #
    # Move your recorded total FORWARD ONLY — never add, and never assign blindly. Delivery is
    # at-least-once and arrival order is not guaranteed: deliveries are not serialized per
    # order, and a failed one is retried after a backoff, so the event carrying 30 can land
    # AFTER the one carrying 50. The late 30 is not a duplicate (different key, correctly
    # processed), so assigning would regress the total from 50 back to 30 and under-refund the
    # customer; adding would over-refund on a redelivery. max() is idempotent AND order-safe.
    # Compare as decimals, not floats or strings ("9.90" > "10.00" lexicographically).
    # See ../../spec/SIGNING.md §3.1.
    puts "  → Refunded so far #{evt['refunded_amount'] || '0'} of order total #{evt['amount']} #{evt['currency']}" \
         " (status=#{evt['status']}; partially_refunded means more may follow)"
    puts "  → Advance your recorded refunded total to max(recorded, refunded_amount) — never assign blindly, and never add"
  end

  # Return 2xx quickly; anything else is retried by fluxa with exponential backoff (up to
  # 8 attempts).
  respond(sock, "200 OK", "ok")
end

# Validate the webhook secret at startup rather than failing on the first callback that
# arrives — the accessor aborts with an actionable message if it is unset.
config.webhook_secret

server = TCPServer.new("0.0.0.0", config.webhook_port)
puts "fluxa webhook receiver listening on http://localhost:#{config.webhook_port}"
puts "Point your portal callback URL here (it must be publicly reachable — use a tunnel such as ngrok for local testing)."

loop do
  sock = server.accept
  Thread.new(sock) do |s|
    begin
      handle(s, config, processed, lock)
    rescue StandardError => e
      warn "✗ Error handling connection: #{e.class}: #{e.message}"
    ensure
      s.close rescue nil
    end
  end
end
