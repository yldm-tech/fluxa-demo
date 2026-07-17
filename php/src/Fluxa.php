<?php

declare(strict_types=1);

// fluxa merchant API client: HMAC request signing + charge + order lookup + webhook
// verification. Dependency-free — only PHP's built-in hash / openssl / curl extensions.
//
// The signing contract is ../../spec/SIGNING.md, pinned by ../../spec/vectors.json.

final class Fluxa
{
    // Every JSON body this client emits uses these flags, and the exact bytes they produce
    // are what gets signed. UNESCAPED_UNICODE emits non-ASCII (an accented name, a CJK
    // product title) as raw UTF-8 rather than \uXXXX escapes; UNESCAPED_SLASHES keeps
    // return_url readable. The flags matter because they change the bytes: flipping either
    // one between signing and sending changes the body hash and the signature dies.
    private const JSON_FLAGS = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR;

    public function __construct(
        private readonly string $baseUrl,
        private readonly string $keyId,
        private readonly string $secret,
    ) {
    }

    // canonicalQuery matches the server's canonical-query normalization (see
    // ../../spec/SIGNING.md §1.1): split the raw query on "&", sort the fragments by UTF-8
    // byte order, rejoin with "&". Empty query -> "".
    // SORT_STRING is required, not decorative: it compares raw bytes (strcmp), matching the
    // server for every input. PHP's default SORT_REGULAR would compare numeric-looking
    // fragments *numerically* ("9" before "10"), silently diverging.
    private static function canonicalQuery(string $raw): string
    {
        if ($raw === '') {
            return ''; // explode('&', '') would return [''], not [] — keep this guard
        }
        $parts = explode('&', $raw);
        sort($parts, SORT_STRING);

        return implode('&', $parts);
    }

    // canonical builds the 5-line string-to-sign. The third line is CANONICAL_QUERY and
    // is an EMPTY LINE when there is no query — dropping it yields a 4-line string whose
    // HMAC the server rejects as bad_signature.
    public static function canonical(
        string $method,
        string $path,
        string $rawQuery,
        string $timestamp,
        string $body,
    ): string {
        $bodyHash = hash('sha256', $body);

        return implode("\n", [
            strtoupper($method),
            $path,
            self::canonicalQuery($rawQuery),
            $timestamp,
            $bodyHash,
        ]);
    }

    // NOTE the argument order: hash_hmac() takes the DATA before the KEY, the reverse of
    // most crypto APIs. Swapping them still returns a plausible-looking hex digest that
    // the server rejects.
    public static function sign(string $secret, string $data): string
    {
        return hash_hmac('sha256', $data, $secret);
    }

    // signedHeaders computes the three auth headers. `path` may carry a query string;
    // it is split and folded into the signature exactly as the server does.
    public static function signedHeaders(
        string $keyId,
        string $secret,
        string $method,
        string $path,
        string $body,
        ?int $nowSeconds = null,
    ): array {
        $ts = (string) ($nowSeconds ?? time());
        $qi = strpos($path, '?');
        $reqPath = $qi === false ? $path : substr($path, 0, $qi);
        $rawQuery = $qi === false ? '' : substr($path, $qi + 1);

        return [
            'X-Api-Key' => $keyId,
            'X-Timestamp' => $ts,
            'X-Signature' => self::sign($secret, self::canonical($method, $reqPath, $rawQuery, $ts, $body)),
        ];
    }

    // request signs and sends one Merchant API call. The body is serialized ONCE and the
    // exact same string is both signed and sent — re-serializing would change key order
    // or spacing and invalidate the signature.
    public function request(string $method, string $path, ?array $payload = null): mixed
    {
        $body = $payload === null ? '' : json_encode($payload, self::JSON_FLAGS);

        $headers = self::signedHeaders($this->keyId, $this->secret, $method, $path, $body);
        $headers['Content-Type'] = 'application/json';
        $headerLines = [];
        foreach ($headers as $name => $value) {
            $headerLines[] = "{$name}: {$value}";
        }

        $ch = curl_init($this->baseUrl . $path);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_TIMEOUT => 30,
        ]);
        if ($body !== '') {
            // Pass the signed STRING, not an array: an array would make cURL switch to
            // multipart/form-data and send bytes that no longer match the signature.
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $text = curl_exec($ch);
        if ($text === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException("{$method} {$path} request failed: {$err}");
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        try {
            $parsed = $text === '' ? null : json_decode($text, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new RuntimeException("HTTP {$status}: response is not valid JSON: " . substr($text, 0, 300));
        }
        if ($status < 200 || $status >= 300) {
            $err = $parsed['error'] ?? $parsed;
            throw new RuntimeException(sprintf(
                'HTTP %d %s %s: %s',
                $status,
                $method,
                $path,
                json_encode($err, self::JSON_FLAGS),
            ));
        }

        return $parsed;
    }

    public function createCharge(array $charge): mixed
    {
        return $this->request('POST', '/api/v1/charges', $charge);
    }

    public function getOrder(string $orderId): mixed
    {
        return $this->request('GET', '/api/v1/orders/' . rawurlencode($orderId));
    }

    // verifyWebhook checks X-Fluxa-Signature over "<timestamp>.<rawBody>". rawBody MUST be
    // the exact received bytes — a re-serialized object will not match.
    // hash_equals is the constant-time compare; it also returns false on length mismatch.
    public static function verifyWebhook(
        string $webhookSecret,
        string $timestamp,
        string $rawBody,
        string $provided,
    ): bool {
        $expected = self::sign($webhookSecret, "{$timestamp}.{$rawBody}");

        return hash_equals($expected, $provided);
    }

    // decryptWebhook opens the AES-256-GCM envelope sent when the platform runs with
    // WEBHOOK_ENCRYPTION=true. Key = SHA256(webhook_secret); blob = nonce[12] || ct || tag[16].
    // Verify the signature BEFORE calling this — the signature covers the envelope.
    public static function decryptWebhook(string $webhookSecret, string $envelopeJson): string
    {
        try {
            $env = json_decode($envelopeJson, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('envelope is not valid JSON: ' . $e->getMessage());
        }
        if (!is_array($env) || !isset($env['data']) || !is_string($env['data'])) {
            throw new RuntimeException('envelope is missing the data field');
        }

        // The third arg of hash() is $binary — this MUST be the raw 32 bytes, not the
        // 64-char hex string, or the key is wrong and every decrypt fails.
        $key = hash('sha256', $webhookSecret, true);
        $blob = base64_decode($env['data'], true);
        if ($blob === false || strlen($blob) < 12 + 16) {
            throw new RuntimeException('envelope data is too short or not valid base64');
        }

        // openssl_decrypt wants the tag SEPARATELY and the ciphertext WITHOUT it. The server
        // appends the tag to the ciphertext, so it has to be sliced back off here. Go, Java
        // and Rust instead pass the trailing tag inline — that split is the most common
        // porting bug in this area.
        $nonce = substr($blob, 0, 12);
        $tag = substr($blob, -16);
        $ciphertext = substr($blob, 12, strlen($blob) - 12 - 16);

        $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
        // openssl_decrypt returns false on a bad key/tag rather than throwing; convert it
        // so callers can rely on a thrown error the way they do in the other demos.
        if ($plaintext === false) {
            throw new RuntimeException('envelope decryption failed: wrong key or tampered ciphertext');
        }

        return $plaintext;
    }
}
