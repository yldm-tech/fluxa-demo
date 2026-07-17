// Known-answer tests: this implementation must reproduce ../spec/vectors.json byte for byte.
// Those vectors are generated from fluxa's actual server-side signing code, which makes them
// the single criterion for a correct port — and checking them needs no running server and no
// credentials.
//
//   mvn test
package cash.fluxa.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VectorsTest {

  private static JsonNode vectors;

  @BeforeAll
  static void loadVectors() throws IOException {
    // Config.repoRoot() walks up to the repo root by marker file, so this does not depend on
    // Maven's working directory.
    Path path = Config.repoRoot().resolve("spec").resolve("vectors.json");
    vectors = new ObjectMapper().readTree(Files.readString(path, StandardCharsets.UTF_8));
  }

  @TestFactory
  @DisplayName("request signing vectors")
  List<DynamicTest> requestVectors() {
    List<DynamicTest> tests = new ArrayList<>();
    for (JsonNode v : vectors.get("requests")) {
      tests.add(
          DynamicTest.dynamicTest(
              v.get("name").asText(),
              () -> {
                String canon =
                    Fluxa.canonical(
                        v.get("method").asText(),
                        v.get("path").asText(),
                        v.get("raw_query").asText(),
                        v.get("timestamp").asText(),
                        v.get("body").asText());
                assertEquals(v.get("canonical").asText(), canon, "canonical string mismatch");
                assertEquals(
                    v.get("signature").asText(),
                    Fluxa.sign(v.get("secret").asText(), canon),
                    "signature mismatch");
              }));
    }
    return tests;
  }

  @Test
  @DisplayName("with no query, line 3 of the canonical is an empty line (5 lines, not 4)")
  void canonicalKeepsEmptyQueryLine() {
    String canon = Fluxa.canonical("POST", "/api/v1/charges", "", "1750000000", "{}");
    String[] lines = canon.split("\n", -1);
    assertEquals(5, lines.length, "canonical must be 5 lines");
    assertEquals("", lines[2], "line 3 (CANONICAL_QUERY) must be the empty string");
  }

  @Test
  @DisplayName("query order does not change the signature, but tampering does")
  void queryOrderIsCanonicalizedButTamperingIsNot() {
    String a = Fluxa.canonical("GET", "/api/v1/orders", "status=paid&limit=10", "1750000000", "");
    String b = Fluxa.canonical("GET", "/api/v1/orders", "limit=10&status=paid", "1750000000", "");
    assertEquals(a, b, "different param order must give the same canonical");

    String tampered =
        Fluxa.canonical("GET", "/api/v1/orders", "status=failed&limit=10", "1750000000", "");
    assertNotEquals(a, tampered, "tampering with a param value must change the canonical");

    String dropped = Fluxa.canonical("GET", "/api/v1/orders", "", "1750000000", "");
    assertNotEquals(a, dropped, "dropping the query must change the canonical");
  }

  @Test
  @DisplayName("query fragments sort in UTF-8 byte order, not Java's UTF-16 order")
  void queryIsSortedByUtf8ByteOrder() {
    // U+FFFD (UTF-8: EF BF BD) versus U+10000 (UTF-8: F0 90 80 80; in UTF-16 the surrogate
    // pair D800 DC00). Java's String.compareTo compares UTF-16 code units and sorts the
    // surrogate pair first; UTF-8 byte order is the opposite — and UTF-8 byte order is what
    // the server uses. The code points are built with Character.toChars to keep this
    // independent of the source file's encoding.
    String supplementary = "a=" + new String(Character.toChars(0x10000));
    String bmp = "a=" + new String(Character.toChars(0xFFFD));
    assertTrue(
        supplementary.compareTo(bmp) < 0,
        "premise: UTF-16 order puts U+10000 before U+FFFD");
    assertEquals(bmp + "&" + supplementary, Fluxa.canonicalQuery(supplementary + "&" + bmp));
  }

  @Test
  @DisplayName("signedHeaders folds a query in the path into the signature")
  void signedHeadersFoldsQueryFromPath() {
    Map<String, String> h =
        Fluxa.signedHeaders("pk_x", "sk_x", "GET", "/api/v1/orders?status=paid&limit=10", "", 1750000000L);
    String want =
        Fluxa.sign("sk_x", Fluxa.canonical("GET", "/api/v1/orders", "status=paid&limit=10", "1750000000", ""));
    assertEquals(want, h.get("X-Signature"));
    assertEquals("1750000000", h.get("X-Timestamp"));
    assertEquals("pk_x", h.get("X-Api-Key"));
  }

  @TestFactory
  @DisplayName("webhook signature vectors")
  List<DynamicTest> webhookVectors() {
    List<DynamicTest> tests = new ArrayList<>();
    for (JsonNode w : vectors.get("webhooks")) {
      tests.add(
          DynamicTest.dynamicTest(
              w.get("name").asText(),
              () -> {
                String secret = w.get("secret").asText();
                String ts = w.get("timestamp").asText();
                String body = w.get("body").asText();
                String signature = w.get("signature").asText();

                assertEquals(signature, Fluxa.sign(secret, w.get("signed_raw").asText()));
                assertTrue(Fluxa.verifyWebhook(secret, ts, body, signature), "should verify");
                assertFalse(
                    Fluxa.verifyWebhook(secret, ts, body + "x", signature),
                    "a tampered body must be rejected");
                assertFalse(
                    Fluxa.verifyWebhook("wrong_secret", ts, body, signature),
                    "a wrong secret must be rejected");
                assertFalse(
                    Fluxa.verifyWebhook(secret, ts, body, ""), "an empty signature must be rejected");
              }));
    }
    return tests;
  }

  @TestFactory
  @DisplayName("AES-256-GCM envelope decryption vectors")
  List<DynamicTest> envelopeVectors() {
    List<DynamicTest> tests = new ArrayList<>();
    for (JsonNode e : vectors.get("envelopes")) {
      tests.add(
          DynamicTest.dynamicTest(
              e.get("name").asText(),
              () -> {
                String envelope = e.get("envelope").asText();
                assertEquals(
                    e.get("plaintext").asText(),
                    Fluxa.decryptWebhook(e.get("secret").asText(), envelope));
                // A wrong key fails GCM's tag check — it must throw, never return garbage
                // plaintext.
                assertThrows(
                    Exception.class,
                    () -> Fluxa.decryptWebhook("wrong_secret", envelope),
                    "a wrong secret must fail to decrypt");
              }));
    }
    return tests;
  }
}
