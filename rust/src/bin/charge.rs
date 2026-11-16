// Charge demo: create a charge, print the payer instruction, then look the order back up
// to confirm its status.
//
//   cargo run --bin charge [merchant_order_id]

use std::collections::BTreeMap;
use std::fmt::Display;
use std::time::{SystemTime, UNIX_EPOCH};

use fluxa::{ChargeRequest, Client};

fn main() {
    let cfg = fluxa::config::load().unwrap_or_else(fatal);
    cfg.require_api_keys().unwrap_or_else(fatal);

    let merchant_order_id = std::env::args().nth(1).unwrap_or_else(|| {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before 1970")
            .as_millis();
        format!("demo-{ms}")
    });

    let charge = ChargeRequest {
        // merchant_order_id is the idempotency key: re-sending the same value returns the
        // same order (idempotent: true) instead of creating a second charge.
        merchant_order_id: merchant_order_id.clone(),
        amount: cfg.amount.clone(), // decimal string — never a float
        currency: cfg.currency.clone(),
        channel: cfg.channel.clone(),
        network: cfg.network.clone(),
        method: cfg.method.clone(),
        presentation: cfg.presentation.clone(),
        subject: "fluxa demo item".to_string(),
        description: "Created by fluxa-demo/rust".to_string(),
        metadata: BTreeMap::from([
            ("source".to_string(), serde_json::json!("fluxa-demo")),
            ("lang".to_string(), serde_json::json!("rust")),
        ]),
        return_url: cfg.return_url.clone(),
        cancel_url: cfg.cancel_url.clone(),
        expires_in_seconds: 1800,
        ..Default::default()
    };

    let client = Client::new(cfg);

    println!("→ POST /api/v1/charges  (merchant_order_id={merchant_order_id})");
    let res = client.create_charge(&charge).unwrap_or_else(fatal);

    let (order, payment, instruction) = (&res.order, &res.payment, &res.instruction);
    println!(
        "✓ Order created {}  status={}  {} {}",
        order.id, order.status, order.amount, order.currency
    );
    if res.idempotent {
        println!("  (idempotent hit: this merchant_order_id already exists — this is the original order)");
    }
    println!(
        "  Channel payment={} channel={}",
        payment.id, payment.channel_code
    );

    // instruction.type decides how to route the payer.
    match instruction.kind.as_str() {
        "redirect" => println!(
            "\nPayer action: send the payer to the checkout page\n  {}",
            instruction.redirect_url
        ),
        "crypto_address" => println!(
            "\nPayer action: transfer to this address\n  Chain: {}  Asset: {}\n  Address: {}\n  Amount: {}\n  Required confirmations: {}",
            instruction.chain,
            instruction.asset,
            instruction.deposit_address,
            instruction.amount_due,
            instruction.required_confirmations
        ),
        "client_secret" => println!(
            "\nPayer action: confirm client-side with the client_secret\n  {}\n  Publishable key: {}",
            instruction.client_secret, instruction.publishable_key
        ),
        "none" => println!("\nNo payable instruction: check order.status; closed orders require a new merchant_order_id."),
        other => println!("\nUnknown instruction.type={other}: {instruction:?}"),
    }

    println!("\n→ GET /api/v1/orders/{}", order.id);
    let detail = client.get_order(&order.id).unwrap_or_else(fatal);
    println!("✓ Looked back up: status={}", detail.order.status);
    println!(
        "\nOnce the order is paid, fluxa POSTs payment.succeeded to the callback URL you\
         \nregistered in the portal. To receive it locally: cargo run --bin webhook\
         \n(your receiver must be publicly reachable — expose it with a tunnel such as ngrok\
         \nand register that URL)."
    );
}

fn fatal<T>(err: impl Display) -> T {
    eprintln!("{err}");
    std::process::exit(1);
}
