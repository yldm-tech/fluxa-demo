// Webhook receiver demo: verify signature -> decrypt (if enabled) -> process idempotently
// -> return 2xx.
//   dotnet run --project FluxaDemo -- webhook
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FluxaDemo;

internal static class Webhook
{
    // Delivery is at-least-once: the same event can arrive more than once, so processing MUST
    // be idempotent. The key is DedupeKey() below. In a real integration this belongs in a
    // database unique constraint (a unique index on order_id + event + refunded_amount); the
    // in-process HashSet is a demo stand-in.
    private static readonly HashSet<string> Processed = new(StringComparer.Ordinal);

    private const int MaxSkewSeconds = 300;
    private const int MaxBodyBytes = 1 << 20;

    /// <summary>
    /// DedupeKey is the idempotency key: <c>event : order_id : refunded_amount</c>.
    ///
    /// <para>The key MUST include refunded_amount. <c>(event, order_id)</c> alone is <b>not
    /// unique</b>: a single order can be partially refunded more than once, and each refund
    /// fires its own payment.refunded. Deduplicating on just that pair drops the second
    /// partial refund as a "duplicate" and returns 2xx — fluxa then records the delivery as
    /// successful and never retries. The customer is under-refunded and nothing errors
    /// anywhere in the chain.</para>
    ///
    /// <para>refunded_amount is cumulative and strictly increasing, so it separates a
    /// redelivery of the same event (same value → deduplicate) from a genuinely new partial
    /// refund (higher value → process).</para>
    ///
    /// <para>payment.succeeded / payment.failed carry no refunded_amount, and Fluxa.Field
    /// returns "" for an absent field, so for them the key degrades to
    /// <c>(event, order_id)</c> — which is correct for those events.</para>
    ///
    /// <para>In a real integration this belongs in a database unique constraint (a unique
    /// index on order_id + event + refunded_amount). See ../../spec/SIGNING.md §3.1.</para>
    /// </summary>
    internal static string DedupeKey(JsonElement evt) =>
        $"{Fluxa.Field(evt, "event")}:{Fluxa.Field(evt, "order_id")}:{Fluxa.Field(evt, "refunded_amount")}";

    // IsTest reads is_test without throwing on an absent property. Only a literal JSON true
    // counts — a missing field is not a test order.
    internal static bool IsTest(JsonElement evt) =>
        evt.ValueKind == JsonValueKind.Object
        && evt.TryGetProperty("is_test", out var v)
        && v.ValueKind == JsonValueKind.True;

    public static async Task<int> RunAsync()
    {
        var cfg = Config.Load();
        // Validate the webhook secret at startup rather than failing on the first callback that
        // arrives — the property exits with an actionable message if it is unset.
        _ = cfg.WebhookSecret;

        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://+:{cfg.WebhookPort}/");
        listener.Start();
        Console.WriteLine($"fluxa webhook receiver listening on http://localhost:{cfg.WebhookPort}");
        Console.WriteLine(
            "Point your portal callback URL here. It must be reachable from the internet, so for"
            + " local testing expose it with a tunnel such as ngrok and register that URL.");

        while (true)
        {
            var ctx = await listener.GetContextAsync();
            await HandleAsync(cfg, ctx);
        }
    }

    private static async Task HandleAsync(Config cfg, HttpListenerContext ctx)
    {
        var req = ctx.Request;
        var res = ctx.Response;

        if (req.HttpMethod != "POST")
        {
            await RespondAsync(res, 405, "only POST");
            return;
        }

        // The signature MUST be verified against the raw received bytes: deserializing and
        // re-serializing changes the bytes and the signature will no longer match.
        var rawBytes = await ReadBodyAsync(req.InputStream, MaxBodyBytes);
        if (rawBytes is null)
        {
            await RespondAsync(res, 413, "body too large");
            return;
        }
        // Verify over the raw bytes (below); the decoded string is only used after the
        // signature passes, for decryption and JSON parsing.
        var rawBody = Encoding.UTF8.GetString(rawBytes);

        var eventName = req.Headers["X-Fluxa-Event"];
        var ts = req.Headers["X-Fluxa-Timestamp"];
        var sig = req.Headers["X-Fluxa-Signature"];
        var encryption = req.Headers["X-Fluxa-Encryption"];

        if (!Fluxa.VerifyWebhook(cfg.WebhookSecret, ts, rawBytes, sig))
        {
            Console.Error.WriteLine($"✗ Signature verification failed, event={eventName} — rejected");
            await RespondAsync(res, 401, "bad signature");
            return;
        }

        // Check the timestamp only after the signature passes, to limit the replay window.
        if (!long.TryParse(ts, out var tsSeconds))
        {
            Console.Error.WriteLine($"✗ Timestamp is not a number (\"{ts}\"), event={eventName} — rejected");
            await RespondAsync(res, 401, "stale timestamp");
            return;
        }
        var skew = Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - tsSeconds);
        if (skew > MaxSkewSeconds)
        {
            Console.Error.WriteLine(
                $"✗ Timestamp outside the allowed window ({skew}s), event={eventName} — rejected");
            await RespondAsync(res, 401, "stale timestamp");
            return;
        }

        // Verify first, then decrypt: the signature covers the envelope body as it was sent.
        var payload = rawBody;
        if (encryption == "A256GCM")
        {
            try
            {
                payload = Fluxa.DecryptWebhook(cfg.WebhookSecret, rawBody);
                Console.WriteLine("  (payload was an AES-256-GCM encrypted envelope; decrypted)");
            }
            catch (Exception e) when (e is CryptographicException or JsonException or FormatException or FluxaException)
            {
                Console.Error.WriteLine($"✗ Decryption failed: {e.Message}");
                await RespondAsync(res, 400, "bad envelope");
                return;
            }
        }

        JsonElement evt;
        try
        {
            using var doc = JsonDocument.Parse(payload);
            evt = doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            await RespondAsync(res, 400, "bad json");
            return;
        }

        var key = DedupeKey(evt);
        if (!Processed.Add(key))
        {
            // Redelivery: already processed, so return 2xx without shipping goods or
            // crediting the account a second time.
            Console.WriteLine($"↺ Duplicate delivery ignored {key}");
            await RespondAsync(res, 200, "ok (duplicate)");
            return;
        }

        Console.WriteLine($"✓ {Fluxa.Field(evt, "event")}  order={Fluxa.Field(evt, "order_id")}  " +
                          $"merchant_order={Fluxa.Field(evt, "merchant_order_id")}");
        Console.WriteLine($"  {Fluxa.Field(evt, "amount")} {Fluxa.Field(evt, "currency")}  " +
                          $"status={Fluxa.Field(evt, "status")}  channel={Fluxa.Field(evt, "channel")}");

        var isTest = IsTest(evt);
        if (isTest)
        {
            // Test-key orders fire real webhooks so merchants can exercise the integration,
            // but no real money moved.
            Console.WriteLine("  ⚠ is_test=true: this is a test order — do not actually ship goods.");
        }

        switch (Fluxa.Field(evt, "event"))
        {
            case "payment.succeeded":
                if (!isTest)
                {
                    Console.WriteLine(
                        "  → Ship goods / grant entitlements here (treat amounts as decimal strings, never floats)");
                }
                break;
            case "payment.failed":
                Console.WriteLine("  → Mark the order failed here");
                break;
            case "payment.refunded":
                // refunded_amount is the CUMULATIVE refunded total, not the amount of this
                // refund; amount is the ORDER TOTAL. Computing a refund from amount would read
                // "1 refunded on a 1000 order" as "1000 refunded".
                //
                // Move your recorded total FORWARD ONLY — never add, and never assign blindly.
                // Delivery is at-least-once and arrival order is not guaranteed: deliveries are
                // not serialized per order, and a failed one is retried after a backoff, so the
                // event carrying 30 can land AFTER the one carrying 50. The late 30 is not a
                // duplicate (different key, correctly processed), so assigning would regress the
                // total from 50 back to 30 and under-refund the customer; adding would
                // over-refund on a redelivery. max(recorded, incoming) is idempotent AND
                // order-safe. Compare as decimal, never double, and never as a string
                // ("9.90" > "10.00" lexicographically). See ../../spec/SIGNING.md §3.1.
                var refunded = Fluxa.Field(evt, "refunded_amount");
                Console.WriteLine(
                    $"  → Refunded so far {(refunded.Length == 0 ? "0" : refunded)} of order total " +
                    $"{Fluxa.Field(evt, "amount")} {Fluxa.Field(evt, "currency")}" +
                    $" (status={Fluxa.Field(evt, "status")}; partially_refunded means more may follow)");
                Console.WriteLine(
                    "  → Advance your recorded refunded total to max(recorded, refunded_amount)" +
                    " — never assign blindly, and never add");
                break;
        }

        // Return 2xx quickly; anything else is retried by fluxa with exponential backoff, up
        // to 8 attempts.
        await RespondAsync(res, 200, "ok");
    }

    // Read the body with a hard cap; returns null when the cap is exceeded.
    private static async Task<byte[]?> ReadBodyAsync(Stream input, int maxBytes)
    {
        using var ms = new MemoryStream();
        var buf = new byte[8192];
        int n;
        while ((n = await input.ReadAsync(buf)) > 0)
        {
            if (ms.Length + n > maxBytes) return null;
            ms.Write(buf, 0, n);
        }
        return ms.ToArray();
    }

    private static async Task RespondAsync(HttpListenerResponse res, int status, string body)
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        res.StatusCode = status;
        res.ContentType = "text/plain; charset=utf-8";
        res.ContentLength64 = bytes.Length;
        await res.OutputStream.WriteAsync(bytes);
        res.Close();
    }
}
