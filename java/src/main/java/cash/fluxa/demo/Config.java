// Loads the shared ../.env so every language demo is driven by one file.
// Real process env wins over .env, so `FLUXA_CHANNEL=stripe mvn ... exec:java` works.
package cash.fluxa.demo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Config {

  public final String baseUrl;
  public final String channel;
  public final String currency;
  public final String amount;
  public final int webhookPort;

  private final Map<String, String> fileEnv;

  private Config(Map<String, String> fileEnv) {
    this.fileEnv = fileEnv;
    this.baseUrl = get("FLUXA_BASE_URL", "http://localhost:8090").replaceAll("/+$", "");
    this.channel = get("FLUXA_CHANNEL", "mock");
    this.currency = get("FLUXA_CURRENCY", "USD");
    this.amount = get("FLUXA_AMOUNT", "9.99");
    this.webhookPort = parsePort(get("WEBHOOK_PORT", "9000"));
  }

  // Config.load() runs for BOTH subcommands, and the charge demo never binds the port, so a
  // malformed WEBHOOK_PORT (including a bare `WEBHOOK_PORT=` line, whose empty value wins over
  // the default) must not abort it with a NumberFormatException from the constructor. Fall
  // back to the default, matching the C# demo's `int.TryParse(...) ? p : 9000`.
  static int parsePort(String raw) {
    try {
      return Integer.parseInt(raw.trim());
    } catch (NumberFormatException e) {
      return 9000;
    }
  }

  // repoRoot walks up from the working directory to the demo repo root — the directory
  // holding both .env.example and spec/. Maven runs tests and exec:java from the module
  // dir, but resolving by marker keeps ../.env and ../spec/vectors.json correct no matter
  // which directory the JVM was started from.
  public static Path repoRoot() {
    Path start = Paths.get("").toAbsolutePath();
    for (Path p = start; p != null; p = p.getParent()) {
      if (Files.isRegularFile(p.resolve(".env.example")) && Files.isDirectory(p.resolve("spec"))) {
        return p;
      }
    }
    // Fallback: the parent of the java module directory is the repo root.
    Path parent = start.getParent();
    return parent != null ? parent : start;
  }

  public static Config load() {
    Path envPath = repoRoot().resolve(".env");
    String text;
    try {
      text = Files.readString(envPath, StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw fatal(
          envPath + " not found — run `cp .env.example .env` at the repo root and fill in your keys.");
    }
    return new Config(parseEnv(text));
  }

  static Map<String, String> parseEnv(String text) {
    Map<String, String> out = new LinkedHashMap<>();
    for (String line : text.split("\n")) {
      String t = line.trim();
      if (t.isEmpty() || t.startsWith("#")) continue;
      int eq = t.indexOf('=');
      if (eq < 0) continue;
      String key = t.substring(0, eq).trim();
      String val = t.substring(eq + 1).trim();
      if (val.length() >= 2
          && ((val.startsWith("\"") && val.endsWith("\"")) || (val.startsWith("'") && val.endsWith("'")))) {
        val = val.substring(1, val.length() - 1);
      }
      out.put(key, val);
    }
    return out;
  }

  private String get(String key, String fallback) {
    String fromProcess = System.getenv(key);
    if (fromProcess != null) return fromProcess;
    return fileEnv.getOrDefault(key, fallback);
  }

  // Secrets are read on demand rather than all at construction time, so the webhook demo
  // still starts when no API key is filled in (and the charge demo still starts without a
  // webhook secret).
  private String required(String key) {
    String v = get(key, null);
    if (v == null || v.isEmpty() || v.endsWith("replace_me")) {
      throw fatal(
          key + " is not filled in yet in .env (current value: " + (v == null ? "unset" : v) + ").");
    }
    return v;
  }

  public String keyId() {
    return required("FLUXA_KEY_ID");
  }

  public String secret() {
    return required("FLUXA_SECRET");
  }

  public String webhookSecret() {
    return required("FLUXA_WEBHOOK_SECRET");
  }

  // fatal prints the message and exits 1; it returns an exception purely so callers can
  // write `throw fatal(...)` and keep definite-assignment analysis happy.
  private static RuntimeException fatal(String message) {
    System.err.println(message);
    System.exit(1);
    return new IllegalStateException(message);
  }
}
