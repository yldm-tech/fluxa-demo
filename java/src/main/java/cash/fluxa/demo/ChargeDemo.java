// Charge demo: create a charge, print the payer instruction, then look the order back up to
// confirm its status.
//   mvn -q compile exec:java -Dexec.mainClass=cash.fluxa.demo.ChargeDemo
package cash.fluxa.demo;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.LinkedHashMap;
import java.util.Map;

public final class ChargeDemo {

  private ChargeDemo() {}

  public static void main(String[] args) throws Exception {
    Config config = Config.load();
    String merchantOrderId = args.length > 0 ? args[0] : "demo-" + System.currentTimeMillis();

    // LinkedHashMap keeps key order stable: the body is serialized once, and the bytes that
    // are signed are the bytes that are sent.
    Map<String, Object> charge = new LinkedHashMap<>();
    // merchant_order_id is the idempotency key: re-sending the same value returns the same
    // order (idempotent: true) instead of creating a second charge.
    charge.put("merchant_order_id", merchantOrderId);
    charge.put("amount", config.amount); // decimal string — never a float
    charge.put("currency", config.currency);
    charge.put("channel", config.channel);
    charge.put("subject", "fluxa demo item");
    charge.put("description", "Created by fluxa-demo/java");
    Map<String, Object> metadata = new LinkedHashMap<>(); // Map.of does not preserve order; key order must be stable
    metadata.put("source", "fluxa-demo");
    metadata.put("lang", "java");
    charge.put("metadata", metadata);
    charge.put("return_url", "https://example.com/pay/success");
    charge.put("cancel_url", "https://example.com/pay/cancel");
    charge.put("expires_in_seconds", 1800);

    System.out.println("→ POST /api/v1/charges  (merchant_order_id=" + merchantOrderId + ")");
    JsonNode res = Fluxa.createCharge(config, charge);

    JsonNode order = res.path("order");
    JsonNode payment = res.path("payment");
    JsonNode instruction = res.path("instruction");
    String orderId = order.path("id").asText();

    System.out.println(
        "✓ Order created " + orderId
            + "  status=" + order.path("status").asText()
            + "  " + order.path("amount").asText() + " " + order.path("currency").asText());
    if (res.path("idempotent").asBoolean(false)) {
      System.out.println(
          "  (idempotent hit: this merchant_order_id already exists — this is the original order)");
    }
    System.out.println(
        "  Channel payment=" + payment.path("id").asText()
            + " channel=" + payment.path("channel_code").asText());

    // instruction.type decides how to route the payer.
    String type = instruction.path("type").asText();
    switch (type) {
      case "redirect" -> System.out.println(
          "\nPayer action: send the payer to the checkout page\n  "
              + instruction.path("redirect_url").asText());
      case "crypto_address" -> System.out.println(
          "\nPayer action: transfer to this address"
              + "\n  Chain: " + instruction.path("chain").asText()
              + "  Asset: " + instruction.path("asset").asText()
              + "\n  Address: " + instruction.path("deposit_address").asText()
              + "\n  Amount: " + instruction.path("amount_due").asText()
              + "\n  Required confirmations: " + instruction.path("required_confirmations").asText());
      case "client_secret" -> System.out.println(
          "\nPayer action: confirm client-side with the client_secret\n  "
              + instruction.path("client_secret").asText());
      case "none" -> System.out.println("\nThis channel needs no payer action.");
      default -> System.out.println("\nUnknown instruction.type=" + type + ": " + instruction);
    }

    System.out.println("\n→ GET /api/v1/orders/" + orderId);
    JsonNode detail = Fluxa.getOrder(config, orderId);
    System.out.println("✓ Looked back up: status=" + detail.path("order").path("status").asText());

    System.out.println(
        "\nOnce the order is paid, fluxa POSTs payment.succeeded to the callback URL you"
            + " registered in the portal."
            + "\nTo receive it locally: mvn -q compile exec:java -Dexec.mainClass=cash.fluxa.demo.WebhookDemo"
            + "\n(your receiver must be publicly reachable — expose it with a tunnel such as ngrok"
            + " and register that URL).");
  }
}
