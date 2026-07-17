# Loads the shared ../../.env so every language demo is driven by one file.
# Real process env wins over .env, so `FLUXA_CHANNEL=stripe ruby lib/charge.rb` works.
require "openssl"

module Fluxa
  class Config
    ENV_PATH = File.expand_path(File.join(__dir__, "..", "..", ".env"))

    # Default instance: .env is read on first use, so a bare require does not exit just
    # because the file is missing.
    def self.default
      @default ||= new
    end

    def initialize(env_path = ENV_PATH)
      @file_env = parse_env(read_env(env_path))
    end

    def base_url
      get("FLUXA_BASE_URL", "http://localhost:8090").sub(%r{/+\z}, "")
    end

    # key_id / secret / webhook_secret are required, but validated only when read — the
    # tests need no credentials at all.
    def key_id
      required("FLUXA_KEY_ID")
    end

    def secret
      required("FLUXA_SECRET")
    end

    def webhook_secret
      required("FLUXA_WEBHOOK_SECRET")
    end

    def channel
      get("FLUXA_CHANNEL", "mock")
    end

    def currency
      get("FLUXA_CURRENCY", "USD")
    end

    def amount
      get("FLUXA_AMOUNT", "9.99") # decimal string — never a float
    end

    def webhook_port
      get("WEBHOOK_PORT", "9000").to_i
    end

    private

    def read_env(path)
      File.read(path)
    rescue Errno::ENOENT, Errno::EACCES
      abort("#{path} not found — run cp .env.example .env in the repo root and fill in your keys.")
    end

    def parse_env(text)
      out = {}
      text.split("\n").each do |line|
        t = line.strip
        next if t.empty? || t.start_with?("#")

        eq = t.index("=")
        next if eq.nil?

        key = t[0...eq].strip
        val = t[(eq + 1)..-1].strip
        val = val[1...-1] if quoted?(val)
        out[key] = val
      end
      out
    end

    def quoted?(val)
      val.length >= 2 &&
        ((val.start_with?('"') && val.end_with?('"')) ||
         (val.start_with?("'") && val.end_with?("'")))
    end

    def get(key, fallback = nil)
      ENV[key] || @file_env[key] || fallback
    end

    def required(key)
      v = get(key)
      if v.nil? || v.empty? || v.end_with?("replace_me")
        abort("#{key} is not filled in in .env (current value: #{v.nil? ? 'unset' : v}).")
      end
      v
    end
  end
end
