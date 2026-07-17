// fluxa merchant API client: HMAC request signing + charge + order lookup + webhook
// verification. Apart from Jackson for JSON, this uses only the JDK's built-in
// java.net.http and javax.crypto.
//
// The signing contract is spec/SIGNING.md at the repo root, pinned by spec/vectors.json.
package cash.fluxa.demo;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public final class Fluxa {

  private Fluxa() {}

  private static final HttpClient HTTP = HttpClient.newHttpClient();
  private static final ObjectMapper JSON = new ObjectMapper();

  // canonicalQuery matches the server's canonical-query normalization (see
  // ../spec/SIGNING.md §1.1): split the raw query on "&", sort the fragments by UTF-8 byte
  // order, rejoin with "&". Empty query -> "".
  //
  // The "-1" limit on split is load-bearing: Java's one-arg String.split drops trailing
  // empty fragments, which would diverge from the server for a query like "a=1&b=".
  static String canonicalQuery(String raw) {
    if (raw == null || raw.isEmpty()) return "";
    String[] parts = raw.split("&", -1);
    Arrays.sort(parts, Fluxa::byteOrder);
    return String.join("&", parts);
  }

  // Sorting by UTF-8 bytes — NOT Java's String.compareTo, which compares UTF-16 code units
  // — matches the server for every possible input, including raw code points above U+FFFF
  // where the two orders diverge. A UTF-16 comparator passes every ASCII test and then
  // fails in production, which is what makes this worth spelling out.
  static int byteOrder(String a, String b) {
    return Arrays.compareUnsigned(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
  }

  // canonical builds the 5-line string-to-sign. The third line is CANONICAL_QUERY and
  // is an EMPTY LINE when there is no query — dropping it yields a 4-line string whose
  // HMAC the server rejects as bad_signature.
  public static String canonical(String method, String path, String rawQuery, String timestamp, String body) {
    String bodyHash = sha256Hex(body == null ? "" : body);
    return String.join(
        "\n",
        method.toUpperCase(Locale.ROOT),
        path,
        canonicalQuery(rawQuery),
        timestamp,
        bodyHash);
  }

  public static String sign(String secret, String data) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
      return hex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("HMAC-SHA256 unavailable", e);
    }
  }

  public static Map<String, String> signedHeaders(
      String keyId, String secret, String method, String path, String body) {
    return signedHeaders(keyId, secret, method, path, body, Instant.now().getEpochSecond());
  }

  // signedHeaders computes the three auth headers. `path` may carry a query string;
  // it is split and folded into the signature exactly as the server does.
  public static Map<String, String> signedHeaders(
      String keyId, String secret, String method, String path, String body, long nowSeconds) {
    String ts = Long.toString(nowSeconds);
    int qi = path.indexOf('?');
    String reqPath = qi >= 0 ? path.substring(0, qi) : path;
    String rawQuery = qi >= 0 ? path.substring(qi + 1) : "";
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("X-Api-Key", keyId);
    headers.put("X-Timestamp", ts);
    headers.put("X-Signature", sign(secret, canonical(method, reqPath, rawQuery, ts, body)));
    return headers;
  }

  // request signs and sends one Merchant API call. The body is serialized ONCE and the
  // exact same string is both signed and sent — re-serializing would change key order
  // or spacing and invalidate the signature.
  public static JsonNode request(Config cfg, String method, String path, Object payload)
      throws IOException, InterruptedException {
    String body = payload == null ? "" : JSON.writeValueAsString(payload);

    HttpRequest.BodyPublisher bodyPublisher =
        body.isEmpty()
            ? HttpRequest.BodyPublishers.noBody()
            : HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8);
    HttpRequest.Builder builder =
        HttpRequest.newBuilder(URI.create(cfg.baseUrl + path))
            .method(method.toUpperCase(Locale.ROOT), bodyPublisher)
            .header("Content-Type", "application/json");
    signedHeaders(cfg.keyId(), cfg.secret(), method, path, body).forEach(builder::header);

    HttpResponse<String> res =
        HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

    String text = res.body();
    JsonNode parsed;
    try {
      parsed = text == null || text.isEmpty() ? null : JSON.readTree(text);
    } catch (JacksonException e) {
      String snippet = text.length() > 300 ? text.substring(0, 300) : text;
      throw new IOException("HTTP " + res.statusCode() + ": response is not valid JSON: " + snippet);
    }
    if (res.statusCode() / 100 != 2) {
      JsonNode err = parsed != null && parsed.has("error") ? parsed.get("error") : parsed;
      throw new IOException("HTTP " + res.statusCode() + " " + method + " " + path + ": " + err);
    }
    return parsed;
  }

  public static JsonNode createCharge(Config cfg, Object charge) throws IOException, InterruptedException {
    return request(cfg, "POST", "/api/v1/charges", charge);
  }

  public static JsonNode getOrder(Config cfg, String orderId) throws IOException, InterruptedException {
    return request(cfg, "GET", "/api/v1/orders/" + urlPathEscape(orderId), null);
  }

  // verifyWebhook checks X-Fluxa-Signature over "<timestamp>.<rawBody>". rawBody MUST be
  // the exact received bytes — a re-serialized object will not match.
  public static boolean verifyWebhook(String webhookSecret, String timestamp, String rawBody, String provided) {
    String expected = sign(webhookSecret, timestamp + "." + rawBody);
    byte[] a = expected.getBytes(StandardCharsets.UTF_8);
    byte[] b = (provided == null ? "" : provided).getBytes(StandardCharsets.UTF_8);
    // MessageDigest.isEqual is the JDK's constant-time comparison — never use String.equals here.
    return MessageDigest.isEqual(a, b);
  }

  // decryptWebhook opens the AES-256-GCM envelope sent when the platform runs with
  // WEBHOOK_ENCRYPTION=true. Key = SHA256(webhook_secret); blob = nonce[12] || ct || tag[16].
  // Verify the signature BEFORE calling this — the signature covers the envelope.
  public static String decryptWebhook(String webhookSecret, String envelopeJson)
      throws GeneralSecurityException, IOException {
    JsonNode env = JSON.readTree(envelopeJson);
    JsonNode data = env.get("data");
    if (data == null || !data.isTextual()) {
      throw new IllegalArgumentException("envelope is missing the data field");
    }
    byte[] key = MessageDigest.getInstance("SHA-256").digest(webhookSecret.getBytes(StandardCharsets.UTF_8));
    byte[] blob = Base64.getDecoder().decode(data.asText());
    if (blob.length < 12 + 16) {
      throw new IllegalArgumentException("envelope data is too short to hold a nonce and a tag");
    }
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    // Java needs the tag length spelled out: 128 bits. The server appends the 16-byte tag
    // to the ciphertext, which is exactly what Cipher expects, so blob[12..] is passed
    // whole. Node, Ruby, PHP and C# instead take the tag as a separate argument — that
    // split is the most common porting bug here.
    cipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, blob, 0, 12));
    return new String(cipher.doFinal(blob, 12, blob.length - 12), StandardCharsets.UTF_8);
  }

  static String sha256Hex(String s) {
    try {
      return hex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  private static String hex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
    }
    return sb.toString();
  }

  // Order ids are opaque; escape the few characters that would otherwise change the path
  // or start a query string. URLEncoder is wrong here — it encodes " " as "+".
  private static String urlPathEscape(String segment) {
    StringBuilder sb = new StringBuilder();
    for (byte b : segment.getBytes(StandardCharsets.UTF_8)) {
      int c = b & 0xff;
      boolean unreserved =
          (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
              || c == '-' || c == '.' || c == '_' || c == '~';
      if (unreserved) {
        sb.append((char) c);
      } else {
        sb.append('%').append(Character.toUpperCase(Character.forDigit((c >> 4) & 0xf, 16)))
            .append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
      }
    }
    return sb.toString();
  }
}
