# fluxa merchant API client: HMAC signing + charge + order lookup + webhook verification.
# Zero dependencies — only the Ruby standard library (openssl / net/http / json).
#
# The signing scheme is specified in ../../spec/SIGNING.md and pinned by ../../spec/vectors.json.
require "openssl"
require "net/http"
require "uri"
require "json"

module Fluxa
  # Raised when receiving an encrypted webhook on a Ruby that cannot do AES-GCM, instead of
  # surfacing an empty-message CipherError.
  class GcmUnavailableError < StandardError; end

  module_function

  # Ruby linked against LibreSSL (typically macOS's system ruby 2.6) cannot do AES-256-GCM
  # at all through the openssl bindings — even encrypting a single block raises
  # OpenSSL::Cipher::CipherError, with an empty message. Fail early with something the
  # caller can act on instead of surfacing that. Only encrypted webhooks are affected.
  def ensure_gcm_available!
    return unless OpenSSL::OPENSSL_VERSION.start_with?("LibreSSL")

    raise GcmUnavailableError,
          "This Ruby (#{RUBY_VERSION}) links #{OpenSSL::OPENSSL_VERSION} (typically macOS's " \
          "system ruby), which cannot do AES-256-GCM at all, so it cannot receive encrypted " \
          "webhooks.\n" \
          "This is a LibreSSL limitation, not a Ruby-version one. Encrypted webhooks need a " \
          "Ruby built against OpenSSL — any version:\n" \
          "  brew install ruby   ->  /opt/homebrew/opt/ruby/bin/ruby lib/webhook.rb\n" \
          "  rbenv install 3.3.6 ->  rbenv shell 3.3.6 && ruby lib/webhook.rb\n" \
          "  docker run --rm -v \"$PWD/..\":/app -w /app/ruby -p 9000:9000 ruby:3.3-slim ruby lib/webhook.rb\n" \
          "Only affects encrypted payloads (off by default); signing, charging, and plaintext " \
          "webhook verification all work fine on this interpreter."
  end

  # canonical_query matches the server's canonical-query normalization (see
  # ../../spec/SIGNING.md §1.1): split the raw query on "&", sort the fragments by UTF-8 byte
  # order, rejoin with "&". Empty query -> "".
  # Ruby's String#<=> compares bytes, so a plain sort is already the server's ordering for
  # every input — including raw code points above U+FFFF, the only place where a UTF-16
  # code-unit sort (JS's default) would diverge.
  # The -1 limit keeps trailing empty fragments ("a&" stays two fragments), matching the
  # server; Ruby's default split silently drops them, which changes the HMAC.
  def canonical_query(raw)
    return "" if raw.nil? || raw.empty?

    raw.split("&", -1).sort.join("&")
  end

  # canonical builds the 5-line string-to-sign. The third line is CANONICAL_QUERY and is
  # an EMPTY LINE when there is no query — dropping it yields a 4-line string whose HMAC
  # the server rejects as bad_signature.
  def canonical(method, path, raw_query, timestamp, body)
    body_hash = OpenSSL::Digest::SHA256.hexdigest(body.to_s)
    [method.to_s.upcase, path, canonical_query(raw_query), timestamp.to_s, body_hash].join("\n")
  end

  def sign(secret, data)
    OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("SHA256"), secret, data)
  end

  # signed_headers computes the three auth headers. `path` may carry a query string; it is
  # split and folded into the signature exactly as the server does.
  def signed_headers(key_id, secret, method, path, body, now_seconds = nil)
    ts = (now_seconds || Time.now.to_i).to_s
    req_path, raw_query = path.split("?", 2)
    {
      "X-Api-Key" => key_id,
      "X-Timestamp" => ts,
      "X-Signature" => sign(secret, canonical(method, req_path, raw_query || "", ts, body))
    }
  end

  # request signs and sends one Merchant API call. The body is serialized ONCE and the exact
  # same string is both signed and sent — re-serializing would change key order or spacing
  # and invalidate the signature.
  def request(cfg, method, path, payload = nil)
    body = payload.nil? ? "" : JSON.generate(payload)
    headers = signed_headers(cfg.key_id, cfg.secret, method, path, body)
                .merge("Content-Type" => "application/json")

    uri = URI.parse(cfg.base_url + path)
    req_class = { "GET" => Net::HTTP::Get, "POST" => Net::HTTP::Post }[method.to_s.upcase]
    raise ArgumentError, "unsupported method #{method}" unless req_class

    req = req_class.new(uri)
    headers.each { |k, v| req[k] = v }
    req.body = body unless body.empty?

    res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") do |http|
      http.request(req)
    end

    text = res.body.to_s
    begin
      parsed = text.empty? ? nil : JSON.parse(text)
    rescue JSON::ParserError
      raise "HTTP #{res.code}: response is not valid JSON: #{text[0, 300]}"
    end
    unless res.is_a?(Net::HTTPSuccess)
      err = parsed.is_a?(Hash) && parsed.key?("error") ? parsed["error"] : parsed
      raise "HTTP #{res.code} #{method} #{path}: #{JSON.generate(err)}"
    end
    parsed
  end

  def create_charge(cfg, charge)
    request(cfg, "POST", "/api/v1/charges", charge)
  end

  def get_order(cfg, order_id)
    request(cfg, "GET", "/api/v1/orders/#{encode_path_segment(order_id)}")
  end

  # Percent-encode one path segment (RFC 3986 unreserved set kept literal).
  # NOT URI.encode_www_form_component: that is *form* encoding, which turns a space into
  # "+" — inside a path a "+" is a literal plus, not a space, so it would query the wrong id.
  def encode_path_segment(str)
    str.to_s.b.gsub(/[^A-Za-z0-9\-_.~]/) { |c| format("%%%02X", c.ord) }
  end

  # verify_webhook checks X-Fluxa-Signature over "<timestamp>.<rawBody>". raw_body MUST be
  # the exact received bytes — a re-serialized object will not match.
  def verify_webhook(webhook_secret, timestamp, raw_body, provided)
    expected = sign(webhook_secret, webhook_signing_input(timestamp, raw_body))
    secure_compare(expected, provided.to_s)
  end

  # The raw body arrives off the socket as ASCII-8BIT. Interpolating it into a UTF-8 string
  # raises Encoding::CompatibilityError as soon as a payload carries non-ASCII bytes, so the
  # signing input is assembled in binary.
  def webhook_signing_input(timestamp, raw_body)
    "#{timestamp}.".b + raw_body.to_s.b
  end

  # Constant-time compare. Ruby 2.6 ships openssl 2.1, which has neither
  # OpenSSL.secure_compare nor OpenSSL.fixed_length_secure_compare (both landed in openssl
  # 2.2 / Ruby 2.7), so this is hand-rolled to behave identically on every version.
  # Length is checked first (a hex signature's length is not secret), then every byte is
  # XOR-accumulated so the running time does not reveal where the first difference is.
  def secure_compare(a, b)
    a = a.to_s.b
    b = b.to_s.b
    return false unless a.bytesize == b.bytesize

    res = 0
    a.bytes.each_with_index { |byte, i| res |= byte ^ b.getbyte(i) }
    res.zero?
  end

  # decrypt_webhook opens the AES-256-GCM envelope sent when the platform runs with
  # WEBHOOK_ENCRYPTION=true. Key = SHA256(webhook_secret); blob = nonce[12] || ct || tag[16].
  # Verify the signature BEFORE calling this — the signature covers the envelope.
  #
  # The real constraints, unlike Go's one-shot Open():
  #   - decrypt must be called before key=/iv=
  #   - the tag is handed over separately via auth_tag=, and update() gets the ciphertext
  #     WITHOUT the tag appended
  #   - the AAD is empty (the server seals with a nil AAD). Setting auth_data = "" and
  #     leaving it unset are equivalent on OpenSSL; it is set here to state the intent.
  # See ../../spec/SIGNING.md §2 for the per-language tag-handling table.
  # Requires an OpenSSL-linked Ruby — see ensure_gcm_available!.
  def decrypt_webhook(webhook_secret, envelope_json)
    ensure_gcm_available!
    env = envelope_json.is_a?(String) ? JSON.parse(envelope_json) : envelope_json
    key = OpenSSL::Digest::SHA256.digest(webhook_secret)
    blob = env["data"].to_s.unpack1("m0") # strict base64, no newlines
    raise ArgumentError, "envelope too short: #{blob.bytesize} bytes" if blob.bytesize < 12 + 16

    nonce = blob.byteslice(0, 12)
    tag = blob.byteslice(blob.bytesize - 16, 16)
    ciphertext = blob.byteslice(12, blob.bytesize - 12 - 16)

    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.decrypt # must precede key=/iv=
    cipher.key = key
    cipher.iv = nonce
    cipher.auth_tag = tag
    cipher.auth_data = ""
    # A wrong key or tampered ciphertext makes final raise OpenSSL::Cipher::CipherError.
    (cipher.update(ciphertext) + cipher.final).force_encoding("UTF-8")
  end
end
