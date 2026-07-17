// Charge demo: create a charge, print the payer instruction, then look the order back up to
// confirm its status.
//   dotnet run --project FluxaDemo -- charge [merchant_order_id]
using System.Text.Json;

namespace FluxaDemo;

internal static class Charge
{
    public static async Task<int> RunAsync(string[] args)
    {
        var cfg = Config.Load();
        var merchantOrderId = args.Length > 0 ? args[0] : $"demo-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";

        // An insertion-ordered dictionary expresses the JSON object: insertion order is
        // serialization order, matching the Node demo's object literal one-to-one.
        var charge = new Dictionary<string, object?>
        {
            // merchant_order_id is the idempotency key: re-sending the same value returns the
            // same order (idempotent: true) instead of creating a second charge.
            ["merchant_order_id"] = merchantOrderId,
            ["amount"] = cfg.Amount, // decimal string — never a float
            ["currency"] = cfg.Currency,
            ["channel"] = cfg.Channel,
            ["subject"] = "fluxa demo item",
            ["description"] = "Created by fluxa-demo/dotnet",
            ["metadata"] = new Dictionary<string, string> { ["source"] = "fluxa-demo", ["lang"] = "dotnet" },
            ["return_url"] = "https://example.com/pay/success",
            ["cancel_url"] = "https://example.com/pay/cancel",
            ["expires_in_seconds"] = 1800,
        };

        Console.WriteLine($"→ POST /api/v1/charges  (merchant_order_id={merchantOrderId})");
        var res = await Fluxa.CreateChargeAsync(cfg, charge);

        var order = res.GetProperty("order");
        var payment = res.GetProperty("payment");
        var instruction = res.GetProperty("instruction");
        var idempotent = res.TryGetProperty("idempotent", out var idem) && idem.ValueKind == JsonValueKind.True;

        var orderId = Fluxa.Field(order, "id");
        Console.WriteLine($"✓ Order created {orderId}  status={Fluxa.Field(order, "status")}  " +
                          $"{Fluxa.Field(order, "amount")} {Fluxa.Field(order, "currency")}");
        if (idempotent)
            Console.WriteLine(
                "  (idempotent hit: this merchant_order_id already exists — this is the original order)");
        Console.WriteLine($"  Channel payment={Fluxa.Field(payment, "id")} channel={Fluxa.Field(payment, "channel_code")}");

        // instruction.type decides how to route the payer.
        var type = Fluxa.Field(instruction, "type");
        switch (type)
        {
            case "redirect":
                Console.WriteLine(
                    $"\nPayer action: send the payer to the checkout page\n  {Fluxa.Field(instruction, "redirect_url")}");
                break;
            case "crypto_address":
                Console.WriteLine(
                    $"\nPayer action: transfer to this address\n  Chain: {Fluxa.Field(instruction, "chain")}  " +
                    $"Asset: {Fluxa.Field(instruction, "asset")}" +
                    $"\n  Address: {Fluxa.Field(instruction, "deposit_address")}" +
                    $"\n  Amount: {Fluxa.Field(instruction, "amount_due")}" +
                    $"\n  Required confirmations: {Fluxa.Field(instruction, "required_confirmations")}");
                break;
            case "client_secret":
                Console.WriteLine(
                    $"\nPayer action: confirm client-side with the client_secret\n  {Fluxa.Field(instruction, "client_secret")}");
                break;
            case "none":
                Console.WriteLine("\nThis channel needs no payer action.");
                break;
            default:
                Console.WriteLine($"\nUnknown instruction.type={type}: {instruction}");
                break;
        }

        Console.WriteLine($"\n→ GET /api/v1/orders/{orderId}");
        var detail = await Fluxa.GetOrderAsync(cfg, orderId);
        Console.WriteLine($"✓ Looked back up: status={Fluxa.Field(detail.GetProperty("order"), "status")}");
        Console.WriteLine(
            "\nOnce the order is paid, fluxa POSTs payment.succeeded to the callback URL you registered" +
            " in the portal." +
            "\nTo receive it locally: dotnet run --project FluxaDemo -- webhook" +
            "\n(your receiver must be publicly reachable — expose it with a tunnel such as ngrok and" +
            " register that URL).");
        return 0;
    }
}
