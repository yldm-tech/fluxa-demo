<?php

declare(strict_types=1);

// Charge demo: create a charge, print the payer instruction, then look the order back up to
// confirm its status.
//   php src/charge.php

require_once __DIR__ . '/Config.php';
require_once __DIR__ . '/Fluxa.php';

$merchantOrderId = $argv[1] ?? 'demo-' . (int) round(microtime(true) * 1000);

$charge = [
    // merchant_order_id is the idempotency key: re-sending the same value returns the same
    // order (idempotent: true) instead of creating a second charge.
    'merchant_order_id' => $merchantOrderId,
    'amount' => Config::amount(), // decimal string — never a float
    'currency' => Config::currency(),
    'channel' => Config::channel(),
    'subject' => 'fluxa demo item',
    'description' => 'Created by fluxa-demo/php',
    'metadata' => ['source' => 'fluxa-demo', 'lang' => 'php'],
    'return_url' => 'https://example.com/pay/success',
    'cancel_url' => 'https://example.com/pay/cancel',
    'expires_in_seconds' => 1800,
];

$fluxa = new Fluxa(Config::baseUrl(), Config::keyId(), Config::secret());

try {
    echo "→ POST /api/v1/charges  (merchant_order_id={$merchantOrderId})\n";
    $res = $fluxa->createCharge($charge);

    $order = $res['order'];
    $payment = $res['payment'];
    $instruction = $res['instruction'];

    echo "✓ Order created {$order['id']}  status={$order['status']}  {$order['amount']} {$order['currency']}\n";
    if ($res['idempotent'] ?? false) {
        echo "  (idempotent hit: this merchant_order_id already exists — this is the original order)\n";
    }
    echo "  Channel payment={$payment['id']} channel={$payment['channel_code']}\n";

    // instruction.type decides how to route the payer.
    switch ($instruction['type']) {
        case 'redirect':
            echo "\nPayer action: send the payer to the checkout page\n  {$instruction['redirect_url']}\n";
            break;
        case 'crypto_address':
            echo "\nPayer action: transfer to this address\n"
                . "  Chain: {$instruction['chain']}  Asset: {$instruction['asset']}\n"
                . "  Address: {$instruction['deposit_address']}\n"
                . "  Amount: {$instruction['amount_due']}\n"
                . "  Required confirmations: {$instruction['required_confirmations']}\n";
            break;
        case 'client_secret':
            echo "\nPayer action: confirm client-side with the client_secret\n  {$instruction['client_secret']}\n";
            break;
        case 'none':
            echo "\nThis channel needs no payer action.\n";
            break;
        default:
            echo "\nUnknown instruction.type={$instruction['type']}: "
                . json_encode($instruction, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
    }

    echo "\n→ GET /api/v1/orders/{$order['id']}\n";
    $detail = $fluxa->getOrder($order['id']);
    echo "✓ Looked back up: status={$detail['order']['status']}\n";

    echo "\nOnce the order is paid, fluxa POSTs payment.succeeded to the callback URL you"
        . " registered in the portal."
        . "\nTo receive it locally: php -S 0.0.0.0:" . Config::webhookPort() . " src/webhook.php"
        . "\n(your receiver must be publicly reachable — expose it with a tunnel such as ngrok"
        . " and register that URL).\n";
} catch (RuntimeException $e) {
    fwrite(STDERR, "✗ {$e->getMessage()}\n");
    exit(1);
}
