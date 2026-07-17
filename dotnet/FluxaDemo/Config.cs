// Loads the shared ../.env from the repo root; every language demo reads that one file.
// Real process env wins over .env, so
// `FLUXA_CHANNEL=stripe dotnet run --project FluxaDemo -- charge` works.
using System.Diagnostics.CodeAnalysis;

namespace FluxaDemo;

public sealed class Config
{
    private readonly Dictionary<string, string> _fileEnv;

    private Config(Dictionary<string, string> fileEnv) => _fileEnv = fileEnv;

    // The repo root: where .env and spec/ live. Found by walking up from the assembly's
    // directory rather than trusting the current working directory — under a test run the CWD
    // is whatever the test host chose, which is not reliable.
    public static string RepoRoot { get; } = FindRepoRoot();

    private static string FindRepoRoot()
    {
        foreach (var start in new[] { AppContext.BaseDirectory, Directory.GetCurrentDirectory() })
        {
            for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
            {
                if (File.Exists(Path.Combine(dir.FullName, ".env.example")) &&
                    Directory.Exists(Path.Combine(dir.FullName, "spec")))
                    return dir.FullName;
            }
        }
        throw new InvalidOperationException(
            "Could not find the repo root (the directory holding .env.example and spec/); "
            + $"searched upwards from {AppContext.BaseDirectory}.");
    }

    public static Config Load()
    {
        var envPath = Path.Combine(RepoRoot, ".env");
        try
        {
            return new Config(ParseEnv(File.ReadAllText(envPath)));
        }
        catch (IOException)
        {
            Fatal($"{envPath} not found — run `cp .env.example .env` at the repo root and fill in your keys.");
            throw; // unreachable: Fatal exits
        }
    }

    private static Dictionary<string, string> ParseEnv(string text)
    {
        var outEnv = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in text.Split('\n'))
        {
            var t = line.Trim();
            if (t.Length == 0 || t.StartsWith('#')) continue;
            var eq = t.IndexOf('=');
            if (eq < 0) continue;
            var key = t[..eq].Trim();
            var val = t[(eq + 1)..].Trim();
            if (val.Length >= 2 &&
                ((val.StartsWith('"') && val.EndsWith('"')) || (val.StartsWith('\'') && val.EndsWith('\''))))
                val = val[1..^1];
            outEnv[key] = val;
        }
        return outEnv;
    }

    private string? Get(string key, string? fallback = null)
    {
        var fromProcess = Environment.GetEnvironmentVariable(key);
        if (!string.IsNullOrEmpty(fromProcess)) return fromProcess;
        return _fileEnv.TryGetValue(key, out var v) ? v : fallback;
    }

    private string Required(string key)
    {
        var v = Get(key);
        if (string.IsNullOrEmpty(v) || v.EndsWith("replace_me", StringComparison.Ordinal))
            Fatal($"{key} is not filled in yet in .env (current value: {v ?? "unset"}).");
        return v!;
    }

    [DoesNotReturn]
    private static void Fatal(string message)
    {
        Console.Error.WriteLine(message);
        Environment.Exit(1);
        throw new InvalidOperationException(message); // unreachable
    }

    // Secret fields are validated on demand — only when the property is evaluated — so the
    // webhook demo needs no API keys configured, and the charge demo needs no webhook secret.
    public string BaseUrl => (Get("FLUXA_BASE_URL", "http://localhost:8090") ?? "").TrimEnd('/');
    public string KeyId => Required("FLUXA_KEY_ID");
    public string Secret => Required("FLUXA_SECRET");
    public string WebhookSecret => Required("FLUXA_WEBHOOK_SECRET");
    public string Channel => Get("FLUXA_CHANNEL", "mock")!;
    public string Currency => Get("FLUXA_CURRENCY", "USD")!;
    public string Amount => Get("FLUXA_AMOUNT", "9.99")!; // decimal string — never a float
    public int WebhookPort => int.TryParse(Get("WEBHOOK_PORT", "9000"), out var p) ? p : 9000;
}
