// Config.load() runs for BOTH subcommands, and the charge demo never binds the webhook port.
// A malformed WEBHOOK_PORT must therefore fall back to the default instead of aborting the
// constructor with a NumberFormatException — matching the C# demo's int.TryParse behaviour.
//
//   mvn test
package cash.fluxa.demo;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ConfigTest {

  @Test
  @DisplayName("a valid WEBHOOK_PORT is parsed")
  void validPortParses() {
    assertEquals(9100, Config.parsePort("9100"));
    assertEquals(9000, Config.parsePort("  9000  ")); // surrounding whitespace is tolerated
  }

  @Test
  @DisplayName("a malformed or empty WEBHOOK_PORT falls back to 9000 instead of throwing")
  void malformedPortFallsBack() {
    // A bare `WEBHOOK_PORT=` line yields "", which must not crash the charge demo.
    assertEquals(9000, Config.parsePort(""));
    assertEquals(9000, Config.parsePort("not-a-number"));
    assertEquals(9000, Config.parsePort("8080abc"));
  }
}
