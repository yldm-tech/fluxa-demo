// fluxa merchant API client: HMAC request signing + charge + order lookup + webhook
// verification. Dependency-free — only .NET's built-in System.Security.Cryptography,
// HttpClient and System.Text.Json.
//
// The signing contract is ../../spec/SIGNING.md, pinned by ../../spec/vectors.json.
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace FluxaDemo;

/// <summary>A fluxa merchant API call failed: a non-2xx HTTP status, a non-JSON response,
/// and so on.</summary>
public sealed class FluxaException : Exception
{
    public FluxaException(string message) : base(message) { }
}

public static class Fluxa
{
    // CanonicalQuery matches the server's canonical-query normalization (see
    // ../../spec/SIGNING.md §1.1): split the raw query on "&", sort the fragments by UTF-8
    // byte order, rejoin with "&". Empty query -> "".
    private static string CanonicalQuery(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) return "";
        var parts = raw.Split('&');
        Array.Sort(parts, ByteOrder);
        return string.Join("&", parts);
    }

    // Sort by raw UTF-8 bytes to match the server. .NET's default string ordering
    // (string.CompareTo / Comparer<string>.Default) is CULTURE-SENSITIVE and would diverge
    // here — a real bug even for ASCII in some locales; even StringComparer.Ordinal compares
    // UTF-16 code units, which disagrees with a byte sort for raw code points above U+FFFF.
    // SequenceCompareTo over byte[] is an unsigned element-wise compare with a length
    // tiebreak, which is exactly the ordering the server uses.
    private static int ByteOrder(string a, string b)
    {
        var ab = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        return ab.AsSpan().SequenceCompareTo(bb.AsSpan());
    }

    // Canonical builds the 5-line string-to-sign. The third line is CANONICAL_QUERY and
    // is an EMPTY LINE when there is no query — dropping it yields a 4-line string whose
    // HMAC the server rejects as bad_signature.
    public static string Canonical(string method, string path, string? rawQuery, string timestamp, string? body)
    {
        var bodyHash = Hex(SHA256.HashData(Encoding.UTF8.GetBytes(body ?? "")));
        return string.Join("\n", method.ToUpperInvariant(), path, CanonicalQuery(rawQuery), timestamp, bodyHash);
    }

    public static string Sign(string secret, string data) =>
        Hex(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(data)));

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    // SignedHeaders computes the three auth headers. `path` may carry a query string;
    // it is split and folded into the signature exactly as the server does.
    public static Dictionary<string, string> SignedHeaders(
        string keyId, string secret, string method, string path, string? body, long? nowSeconds = null)
    {
        var ts = (nowSeconds ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            .ToString(CultureInfo.InvariantCulture);
        var qi = path.IndexOf('?');
        var reqPath = qi >= 0 ? path[..qi] : path;
        var rawQuery = qi >= 0 ? path[(qi + 1)..] : "";
        return new Dictionary<string, string>
        {
            ["X-Api-Key"] = keyId,
            ["X-Timestamp"] = ts,
            ["X-Signature"] = Sign(secret, Canonical(method, reqPath, rawQuery, ts, body)),
        };
    }

    private static readonly HttpClient Http = new();

    // UnsafeRelaxedJsonEscaping keeps non-ASCII as raw UTF-8. By default System.Text.Json
    // escapes it into \uXXXX sequences instead, so an accented name or a CJK product title
    // goes out as escapes rather than the literal characters. That is still valid JSON and
    // still self-consistent — we sign the very bytes we send either way — but it would put
    // this demo's wire bytes out of step with the Node/Go ones. "Serialize once, sign and
    // send the same bytes" is what actually keeps the signature valid; this only settles
    // WHICH bytes those are.
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    // RequestAsync signs and sends one Merchant API call. The body is serialized ONCE and the
    // exact same bytes are both signed and sent — re-serializing would change key order or
    // spacing and invalidate the signature.
    public static async Task<JsonElement> RequestAsync(
        Config cfg, HttpMethod method, string path, object? payload = null)
    {
        var body = payload is null ? "" : JsonSerializer.Serialize(payload, JsonOpts);
        var bodyBytes = Encoding.UTF8.GetBytes(body);

        using var req = new HttpRequestMessage(method, cfg.BaseUrl + path);
        foreach (var (name, value) in SignedHeaders(cfg.KeyId, cfg.Secret, method.Method, path, body))
            req.Headers.TryAddWithoutValidation(name, value);
        if (bodyBytes.Length > 0)
        {
            req.Content = new ByteArrayContent(bodyBytes);
            req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }

        using var res = await Http.SendAsync(req);
        var text = await res.Content.ReadAsStringAsync();

        JsonElement parsed = default;
        if (text.Length > 0)
        {
            try
            {
                using var doc = JsonDocument.Parse(text);
                parsed = doc.RootElement.Clone(); // Clone: RootElement dies with the document.
            }
            catch (JsonException)
            {
                var head = text.Length > 300 ? text[..300] : text;
                throw new FluxaException($"HTTP {(int)res.StatusCode}: response is not valid JSON: {head}");
            }
        }
        if (!res.IsSuccessStatusCode)
        {
            var err = parsed.ValueKind == JsonValueKind.Object && parsed.TryGetProperty("error", out var e)
                ? e
                : parsed;
            throw new FluxaException($"HTTP {(int)res.StatusCode} {method.Method} {path}: {err}");
        }
        return parsed;
    }

    public static Task<JsonElement> CreateChargeAsync(Config cfg, object charge) =>
        RequestAsync(cfg, HttpMethod.Post, "/api/v1/charges", charge);

    public static Task<JsonElement> GetOrderAsync(Config cfg, string orderId) =>
        RequestAsync(cfg, HttpMethod.Get, $"/api/v1/orders/{Uri.EscapeDataString(orderId)}");

    // VerifyWebhook checks X-Fluxa-Signature over "<timestamp>.<rawBody>". rawBody MUST be
    // the exact received bytes — a re-serialized object will not match.
    // Freshness is deliberately NOT checked here: this is the pure HMAC step, and the replay
    // window belongs to the caller (see Webhook.cs).
    public static bool VerifyWebhook(string webhookSecret, string? timestamp, string rawBody, string? provided)
    {
        var expected = Sign(webhookSecret, $"{timestamp}.{rawBody}");
        var a = Encoding.UTF8.GetBytes(expected);
        var b = Encoding.UTF8.GetBytes(provided ?? "");
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    // DecryptWebhook opens the AES-256-GCM envelope sent when the platform runs with
    // WEBHOOK_ENCRYPTION=true. Key = SHA256(webhook_secret); blob = nonce[12] || ct || tag[16].
    // Verify the signature BEFORE calling this — the signature covers the envelope.
    //
    // The server appends the tag to the ciphertext, and Go/Java/Rust hand blob[12:]
    // (ciphertext+tag) to the AEAD in one piece. .NET's AesGcm instead takes nonce,
    // ciphertext and tag as SEPARATE spans, so the trailing 16-byte tag is split off here —
    // that split is the most common porting bug in this area. .NET 8's AesGcm constructor
    // also wants the tag size stated explicitly.
    public static string DecryptWebhook(string webhookSecret, string envelopeJson)
    {
        using var doc = JsonDocument.Parse(envelopeJson);
        var data = doc.RootElement.GetProperty("data").GetString()
            ?? throw new FluxaException("envelope is missing the data field");
        var blob = Convert.FromBase64String(data);
        if (blob.Length < 12 + 16) throw new FluxaException($"envelope is too short: {blob.Length} bytes");

        var key = SHA256.HashData(Encoding.UTF8.GetBytes(webhookSecret));
        var nonce = blob.AsSpan(0, 12);
        var tag = blob.AsSpan(blob.Length - 16, 16);
        var ciphertext = blob.AsSpan(12, blob.Length - 12 - 16);

        var plaintext = new byte[ciphertext.Length];
        using var gcm = new AesGcm(key, 16);
        gcm.Decrypt(nonce, ciphertext, tag, plaintext); // throws on a bad key/tag
        return Encoding.UTF8.GetString(plaintext);
    }

    // Field reads one JSON field as text: strings unwrapped, everything else kept as its raw
    // token. Amounts stay decimal strings and never touch a float.
    public static string Field(JsonElement obj, string name) =>
        obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var v)
            ? (v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ToString())
            : "";
}
