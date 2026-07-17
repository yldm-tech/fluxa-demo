# Charge demo: create a charge, print the payer instruction, then read the order back.
#   ruby lib/charge.rb
require_relative "fluxa"
require_relative "config"

config = Fluxa::Config.default
merchant_order_id = ARGV[0] || "demo-#{Time.now.to_i}"

charge = {
  # merchant_order_id is the idempotency key: re-sending the same value returns the same
  # order (idempotent: true) instead of creating a second charge.
  "merchant_order_id" => merchant_order_id,
  "amount" => config.amount, # decimal string — never a float
  "currency" => config.currency,
  "channel" => config.channel,
  "subject" => "fluxa demo item",
  "description" => "Created by fluxa-demo/ruby",
  "metadata" => { "source" => "fluxa-demo", "lang" => "ruby" },
  "return_url" => "https://example.com/pay/success",
  "cancel_url" => "https://example.com/pay/cancel",
  "expires_in_seconds" => 1800
}

puts "→ POST /api/v1/charges  (merchant_order_id=#{merchant_order_id})"
res = Fluxa.create_charge(config, charge)

order = res["order"]
payment = res["payment"]
instruction = res["instruction"] || {}

puts "✓ Order created #{order['id']}  status=#{order['status']}  #{order['amount']} #{order['currency']}"
puts "  (idempotent hit: this merchant_order_id already existed — returning the original order)" if res["idempotent"]
puts "  Channel payment=#{payment['id']} channel=#{payment['channel_code']}"

# instruction.type decides how to drive the payer.
case instruction["type"]
when "redirect"
  puts "\nPayment method: send the payer to the checkout page\n  #{instruction['redirect_url']}"
when "crypto_address"
  puts "\nPayment method: transfer to this address" \
       "\n  Chain: #{instruction['chain']}  Asset: #{instruction['asset']}" \
       "\n  Address: #{instruction['deposit_address']}" \
       "\n  Amount due: #{instruction['amount_due']}" \
       "\n  Required confirmations: #{instruction['required_confirmations']}"
when "client_secret"
  puts "\nPayment method: confirm client-side with client_secret\n  #{instruction['client_secret']}"
when "none"
  puts "\nThis channel needs no payer action."
else
  puts "\nUnknown instruction.type=#{instruction['type']}: #{instruction.inspect}"
end

puts "\n→ GET /api/v1/orders/#{order['id']}"
detail = Fluxa.get_order(config, order["id"])
puts "✓ Read back status=#{detail['order']['status']}"
puts "\nOnce the order is paid, fluxa POSTs payment.succeeded to the callback URL registered in the portal." \
     "\nTo receive it locally: ruby lib/webhook.rb (your callback URL must be publicly reachable — use a tunnel such as ngrok)."
