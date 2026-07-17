// Known-answer tests: this implementation must reproduce ../../spec/vectors.json byte for
// byte. Those vectors are generated from fluxa's actual server-side signing code, which makes
// them the single criterion for a correct port — and checking them needs no running server and
// no credentials.
//
//   dotnet test
using System.Security.Cryptography;
using Xunit;

namespace FluxaDemo.Tests;

public class VectorsTests
{
    private static readonly Vectors V = Vectors.Load();

    // Theory data is passed by name (a plain serializable string) and looked up in the test,
    // so every vector shows up as its own named case in the runner output.
    public static IEnumerable<object[]> RequestNames() => V.Requests.Select(r => new object[] { r.Name });
    public static IEnumerable<object[]> WebhookNames() => V.Webhooks.Select(w => new object[] { w.Name });
    public static IEnumerable<object[]> EnvelopeNames() => V.Envelopes.Select(e => new object[] { e.Name });

    [Theory(DisplayName = "request signing vectors")]
    [MemberData(nameof(RequestNames))]
    public void RequestVectors(string name)
    {
        var v = V.Requests.Single(r => r.Name == name);
        var canon = Fluxa.Canonical(v.Method, v.Path, v.RawQuery, v.Timestamp, v.Body);
        Assert.Equal(v.Canonical, canon);                       // canonical string mismatch
        Assert.Equal(v.Signature, Fluxa.Sign(v.Secret, canon)); // signature mismatch
    }

    [Fact(DisplayName = "with no query, line 3 of the canonical is an empty line (5 lines, not 4)")]
    public void NoQueryCanonicalHasEmptyThirdLine()
    {
        var canon = Fluxa.Canonical("POST", "/api/v1/charges", "", "1750000000", "{}");
        var lines = canon.Split('\n');
        Assert.Equal(5, lines.Length);  // the canonical must be 5 lines
        Assert.Equal("", lines[2]);     // line 3 (CANONICAL_QUERY) must be the empty string
    }

    [Fact(DisplayName = "query order does not change the signature, but tampering does")]
    public void QueryOrderDoesNotChangeSignatureButTamperingDoes()
    {
        var a = Fluxa.Canonical("GET", "/api/v1/orders", "status=paid&limit=10", "1750000000", "");
        var b = Fluxa.Canonical("GET", "/api/v1/orders", "limit=10&status=paid", "1750000000", "");
        Assert.Equal(a, b);                                       // param order must not matter
        Assert.Equal(Fluxa.Sign("sk_x", a), Fluxa.Sign("sk_x", b));

        var tampered = Fluxa.Canonical("GET", "/api/v1/orders", "status=failed&limit=10", "1750000000", "");
        Assert.NotEqual(a, tampered);                             // tampering must change the canonical

        var dropped = Fluxa.Canonical("GET", "/api/v1/orders", "", "1750000000", "");
        Assert.NotEqual(a, dropped);                              // dropping the query must change it
    }

    [Fact(DisplayName = "query fragments sort in UTF-8 byte order, not UTF-16 code-unit order")]
    public void QueryFragmentsSortByUtf8ByteOrder()
    {
        // U+FFFF is UTF-8 "EF BF BF"; U+10000 is "F0 90 80 80" — so U+FFFF sorts FIRST by
        // bytes, matching the server. In UTF-16 U+10000 is the surrogate pair D800 DC00, which
        // sorts BEFORE FFFF — StringComparer.Ordinal would emit the opposite order here, and
        // the culture-sensitive default comparer is anybody's guess.
        var canon = Fluxa.Canonical("GET", "/x", "a=\U00010000&a=￿", "1750000000", "");
        Assert.Equal("a=￿&a=\U00010000", canon.Split('\n')[2]);
    }

    [Fact(DisplayName = "SignedHeaders folds a query in the path into the signature")]
    public void SignedHeadersFoldsQueryFromPath()
    {
        var h = Fluxa.SignedHeaders("pk_x", "sk_x", "GET", "/api/v1/orders?status=paid&limit=10", "", 1750000000);
        var want = Fluxa.Sign("sk_x",
            Fluxa.Canonical("GET", "/api/v1/orders", "status=paid&limit=10", "1750000000", ""));
        Assert.Equal(want, h["X-Signature"]);
        Assert.Equal("1750000000", h["X-Timestamp"]);
        Assert.Equal("pk_x", h["X-Api-Key"]);
    }

    [Theory(DisplayName = "webhook signature vectors")]
    [MemberData(nameof(WebhookNames))]
    public void WebhookVectors(string name)
    {
        var w = V.Webhooks.Single(x => x.Name == name);
        Assert.Equal(w.Signature, Fluxa.Sign(w.Secret, w.SignedRaw));
        Assert.True(Fluxa.VerifyWebhook(w.Secret, w.Timestamp, w.Body, w.Signature));        // should verify
        Assert.False(Fluxa.VerifyWebhook(w.Secret, w.Timestamp, w.Body + "x", w.Signature)); // tampered body
        Assert.False(Fluxa.VerifyWebhook("wrong_secret", w.Timestamp, w.Body, w.Signature)); // wrong secret
        Assert.False(Fluxa.VerifyWebhook(w.Secret, w.Timestamp, w.Body, ""));                // empty signature
        Assert.False(Fluxa.VerifyWebhook(w.Secret, w.Timestamp, w.Body, null));              // missing header
        Assert.False(Fluxa.VerifyWebhook(w.Secret, "1750000001", w.Body, w.Signature));      // altered timestamp
    }

    [Theory(DisplayName = "AES-256-GCM envelope decryption vectors")]
    [MemberData(nameof(EnvelopeNames))]
    public void EnvelopeVectors(string name)
    {
        var e = V.Envelopes.Single(x => x.Name == name);
        Assert.Equal(e.Plaintext, Fluxa.DecryptWebhook(e.Secret, e.Envelope));
        // A wrong secret must fail to decrypt. AesGcm throws AuthenticationTagMismatchException,
        // a SUBCLASS of CryptographicException — hence ThrowsAny; Throws<T> demands an exact
        // type match and would fail here.
        Assert.ThrowsAny<CryptographicException>(() => Fluxa.DecryptWebhook("wrong_secret", e.Envelope));
    }

    [Fact(DisplayName = "encrypted envelope: verify first, then decrypt")]
    public void EnvelopeIsVerifiedBeforeDecrypt()
    {
        var e = V.Envelopes.Single();
        // The signature covers the envelope body as sent, not the decrypted plaintext.
        const string ts = "1750000000";
        var sig = Fluxa.Sign(e.Secret, $"{ts}.{e.Envelope}");
        Assert.True(Fluxa.VerifyWebhook(e.Secret, ts, e.Envelope, sig));
        Assert.Equal(e.Plaintext, Fluxa.DecryptWebhook(e.Secret, e.Envelope));
    }
}
