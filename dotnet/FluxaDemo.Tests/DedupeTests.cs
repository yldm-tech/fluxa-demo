// Regression tests for the idempotency key.
//
// fluxa allows an order to be partially refunded more than once — further refunds are allowed
// until refunded_amount reaches the order total — and every refund fires its own
// payment.refunded event. So (event, order_id) is NOT unique.
//
// Deduplicating on just (event, order_id) silently drops the second partial refund and returns
// 2xx, so fluxa records the delivery as successful and never retries. The customer is
// under-refunded and nothing errors anywhere in the chain. These tests pin the correct
// behaviour. See ../../spec/SIGNING.md §3.1.
//
//   dotnet test
using System.Globalization;
using System.Text.Json;
using Xunit;

namespace FluxaDemo.Tests;

public class DedupeTests
{
    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement.Clone();

    /// <summary>The tempting-but-wrong key these tests falsify. Kept so nobody "simplifies"
    /// back to it.</summary>
    private static string BrokenKey(JsonElement evt) =>
        $"{Fluxa.Field(evt, "event")}:{Fluxa.Field(evt, "order_id")}";

    /// <summary>Builds a partial-refund event. <c>cumulative</c> is the <b>cumulative</b>
    /// refunded total.</summary>
    private static JsonElement Refund(string cumulative, string status = "partially_refunded") =>
        Parse($$"""
        {
          "event": "payment.refunded",
          "order_id": "ord_X",
          "merchant_order_id": "o-1",
          "amount": "1000.00",
          "refunded_amount": "{{cumulative}}",
          "currency": "USD",
          "status": "{{status}}",
          "channel": "mock"
        }
        """);

    [Fact(DisplayName = "two partial refunds must have different idempotency keys")]
    public void TwoPartialRefundsGetDifferentKeys()
    {
        var first = Refund("30.00");
        var second = Refund("50.00"); // cumulative: 30 + 20

        // If two partial refunds are judged the same event, the second gets dropped.
        Assert.NotEqual(Webhook.DedupeKey(first), Webhook.DedupeKey(second));

        // Pins the trap itself: the naive key really does collide on these two.
        Assert.Equal(BrokenKey(first), BrokenKey(second));
    }

    [Fact(DisplayName = "a redelivery of the same event must hit the same idempotency key")]
    public void RedeliveryHitsSameKey()
    {
        // fluxa redelivers the identical payload.
        Assert.Equal(Webhook.DedupeKey(Refund("30.00")), Webhook.DedupeKey(Refund("30.00")));
    }

    [Fact(DisplayName = "a full refund differs from an earlier partial refund")]
    public void FullRefundDiffersFromEarlierPartial()
    {
        Assert.NotEqual(
            Webhook.DedupeKey(Refund("30.00")),
            Webhook.DedupeKey(Refund("1000.00", "refunded")));
    }

    [Fact(DisplayName = "payment.succeeded has no refunded_amount, so the key degrades to (event, order_id)")]
    public void SucceededWithoutRefundedAmountDegrades()
    {
        // An absent field must not throw, and must degrade to the old shape (trailing empty part).
        var ok = Parse("""{"event":"payment.succeeded","order_id":"ord_X","status":"paid"}""");
        Assert.Equal("payment.succeeded:ord_X:", Webhook.DedupeKey(ok));
        // A redelivery must be deduplicated.
        Assert.Equal(Webhook.DedupeKey(ok), Webhook.DedupeKey(Parse(ok.GetRawText())));
    }

    [Fact(DisplayName = "a JSON-null refunded_amount degrades too, rather than becoming the literal \"null\"")]
    public void ExplicitNullRefundedAmountDegrades()
    {
        var ok = Parse("""{"event":"payment.succeeded","order_id":"ord_X","refunded_amount":null}""");
        Assert.Equal("payment.succeeded:ord_X:", Webhook.DedupeKey(ok));
    }

    [Fact(DisplayName = "succeeded and refunded are different keys")]
    public void SucceededAndRefundedDiffer()
    {
        var ok = Parse("""{"event":"payment.succeeded","order_id":"ord_X"}""");
        Assert.NotEqual(Webhook.DedupeKey(ok), Webhook.DedupeKey(Refund("30.00")));
    }

    [Fact(DisplayName = "an absent is_test means not a test order; only a literal true counts")]
    public void IsTestOnlyTrueForLiteralTrue()
    {
        Assert.False(Webhook.IsTest(Parse("""{"event":"payment.succeeded","order_id":"ord_X"}""")));
        Assert.True(Webhook.IsTest(Parse("""{"event":"payment.succeeded","is_test":true}""")));
        Assert.False(Webhook.IsTest(Parse("""{"event":"payment.succeeded","is_test":false}""")));
    }

    [Fact(DisplayName = "end to end: both partial refunds against a 1000 order must be processed")]
    public void EndToEndBothPartialRefundsProcessed()
    {
        // The real-world scenario: a 1000 order refunded 30, then 20 (cumulative 50).
        var processed = new HashSet<string>(StringComparer.Ordinal);

        Assert.True(processed.Add(Webhook.DedupeKey(Refund("30.00"))));   // the first refund is processed
        Assert.False(processed.Add(Webhook.DedupeKey(Refund("30.00"))));  // a redelivery is deduplicated
        Assert.True(processed.Add(Webhook.DedupeKey(Refund("50.00"))));   // the second — the one the naive key drops
        Assert.False(processed.Add(Webhook.DedupeKey(Refund("50.00"))));  // a redelivery is deduplicated

        // Cumulative semantics: the latest refunded_amount IS the total to record — never add
        // the events up. See the ordering tests below for why it is advanced with max().
        Assert.Equal("50.00", Fluxa.Field(Refund("50.00"), "refunded_amount"));
    }

    // --- Ordering ---
    //
    // at-least-once says nothing about ORDER. Deliveries are not serialized per order, and a
    // failed delivery is retried after a backoff — so the event carrying the 30 can land after
    // the one carrying 50.
    //
    // Dedupe alone does not save you here: a late 30 is a DIFFERENT key from 50, so it is
    // correctly not a duplicate — it gets processed, and a blind assignment regresses the
    // recorded total. Advancing to max(recorded, incoming) is idempotent AND order-safe.

    /// <summary>
    /// Moves the recorded total forward only. Cumulative totals are decimal strings: parse them
    /// with <c>decimal</c>, never <c>double</c> (the bug the rest of this repo warns about), and
    /// never compare as plain strings ("9.90" > "10.00" ordinally).
    /// InvariantCulture is required — decimal.Parse is culture-sensitive, and in a
    /// comma-decimal locale "9.90" would otherwise parse as 990.
    /// </summary>
    private static string Advance(string recorded, string incoming) =>
        decimal.Parse(incoming, CultureInfo.InvariantCulture) > decimal.Parse(recorded, CultureInfo.InvariantCulture)
            ? incoming
            : recorded;

    [Fact(DisplayName = "out-of-order refunds must not regress the recorded total")]
    public void OutOfOrderRefundsMustNotRegress()
    {
        var recorded = "0";

        // The 50 lands first (the 30's delivery failed and is still backing off).
        recorded = Advance(recorded, Fluxa.Field(Refund("50.00"), "refunded_amount"));
        Assert.Equal("50.00", recorded);

        // The 30 arrives late on retry. It is NOT a duplicate — different key — so it is
        // processed. A blind assignment would drop the total back to 30.
        recorded = Advance(recorded, Fluxa.Field(Refund("30.00"), "refunded_amount"));
        Assert.Equal("50.00", recorded);
    }

    [Fact(DisplayName = "in-order refunds still advance normally")]
    public void InOrderRefundsAdvance()
    {
        var recorded = "0";
        recorded = Advance(recorded, "30.00");
        Assert.Equal("30.00", recorded);
        recorded = Advance(recorded, "50.00");
        Assert.Equal("50.00", recorded);
        recorded = Advance(recorded, "1000.00"); // fully refunded
        Assert.Equal("1000.00", recorded);
    }

    [Fact(DisplayName = "a redelivery of the same cumulative value is a no-op")]
    public void RedeliveryOfSameCumulativeIsNoop()
    {
        Assert.Equal("50.00", Advance("50.00", "50.00"));
    }

    [Fact(DisplayName = "Advance compares as decimals, not floats or strings")]
    public void AdvanceComparesAsDecimals()
    {
        Assert.Equal("50.00", Advance("30.00", "50.00"));
        Assert.Equal("50.00", Advance("50.00", "30.00"));
        // A naive string compare gets this wrong: "9.90" > "10.00" ordinally.
        Assert.Equal("10.00", Advance("9.90", "10.00"));
        Assert.Equal("10.00", Advance("10.00", "9.90"));
    }
}
