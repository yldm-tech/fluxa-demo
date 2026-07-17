// Loading and type mapping for ../../spec/vectors.json.
using System.Text.Json;

namespace FluxaDemo.Tests;

public sealed record RequestVector
{
    public string Name { get; init; } = "";
    public string Method { get; init; } = "";
    public string Path { get; init; } = "";
    public string RawQuery { get; init; } = "";
    public string Timestamp { get; init; } = "";
    public string Body { get; init; } = "";
    public string Secret { get; init; } = "";
    public string Canonical { get; init; } = "";
    public string Signature { get; init; } = "";
}

public sealed record WebhookVector
{
    public string Name { get; init; } = "";
    public string Timestamp { get; init; } = "";
    public string Body { get; init; } = "";
    public string Secret { get; init; } = "";
    public string SignedRaw { get; init; } = "";
    public string Signature { get; init; } = "";
}

public sealed record EnvelopeVector
{
    public string Name { get; init; } = "";
    public string Secret { get; init; } = "";
    public string Envelope { get; init; } = "";
    public string Plaintext { get; init; } = "";
}

public sealed record Vectors
{
    public List<RequestVector> Requests { get; init; } = new();
    public List<WebhookVector> Webhooks { get; init; } = new();
    public List<EnvelopeVector> Envelopes { get; init; } = new();

    // SnakeCaseLower maps raw_query -> RawQuery, signed_raw -> SignedRaw.
    private static readonly JsonSerializerOptions Opts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    // Resolve spec/vectors.json from the repo root rather than the CWD: the test host's
    // working directory is not reliable.
    public static Vectors Load()
    {
        var path = System.IO.Path.Combine(Config.RepoRoot, "spec", "vectors.json");
        return JsonSerializer.Deserialize<Vectors>(File.ReadAllText(path), Opts)
               ?? throw new InvalidOperationException($"{path} parsed as empty");
    }
}
