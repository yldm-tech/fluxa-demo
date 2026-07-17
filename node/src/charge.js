// Charge demo: create a charge, print the payer instruction, then read the order back.
//   node src/charge.js
import { config } from "./config.js";
import { createCharge, getOrder } from "./fluxa.js";

const merchantOrderId = process.argv[2] ?? `demo-${Date.now()}`;

const charge = {
  // merchant_order_id is the idempotency key: re-sending the same value returns the
  // same order (idempotent: true) instead of creating a second charge.
  merchant_order_id: merchantOrderId,
  amount: config.amount, // decimal string — never a float
  currency: config.currency,
  channel: config.channel,
  subject: "fluxa demo item",
  description: "Created by fluxa-demo/node",
  metadata: { source: "fluxa-demo", lang: "node" },
  return_url: "https://example.com/pay/success",
  cancel_url: "https://example.com/pay/cancel",
  expires_in_seconds: 1800,
};

console.log(`→ POST /api/v1/charges  (merchant_order_id=${merchantOrderId})`);
const res = await createCharge(config, charge);

const { order, payment, instruction, idempotent } = res;
console.log(`✓ Order created ${order.id}  status=${order.status}  ${order.amount} ${order.currency}`);
if (idempotent) console.log("  (idempotent hit: this merchant_order_id already existed — returning the original order)");
console.log(`  Channel payment=${payment.id} channel=${payment.channel_code}`);

// instruction.type decides how to drive the payer.
switch (instruction.type) {
  case "redirect":
    console.log(`\nPayment method: send the payer to the checkout page\n  ${instruction.redirect_url}`);
    break;
  case "crypto_address":
    console.log(
      `\nPayment method: transfer to this address\n  Chain: ${instruction.chain}  Asset: ${instruction.asset}` +
        `\n  Address: ${instruction.deposit_address}\n  Amount due: ${instruction.amount_due}` +
        `\n  Required confirmations: ${instruction.required_confirmations}`,
    );
    break;
  case "client_secret":
    console.log(`\nPayment method: confirm client-side with client_secret\n  ${instruction.client_secret}`);
    break;
  case "none":
    console.log("\nThis channel needs no payer action.");
    break;
  default:
    console.log(`\nUnknown instruction.type=${instruction.type}:`, instruction);
}

console.log(`\n→ GET /api/v1/orders/${order.id}`);
const detail = await getOrder(config, order.id);
console.log(`✓ Read back status=${detail.order.status}`);
console.log(
  "\nOnce the order is paid, fluxa POSTs payment.succeeded to the callback URL registered in the portal." +
    "\nTo receive it locally: node src/webhook.js (your callback URL must be publicly reachable — use a tunnel such as ngrok).",
);
