<?php

declare(strict_types=1);

// Webhook receiver demo: verify signature -> decrypt (if enabled) -> process idempotently
// -> return 2xx.
// Runs under PHP's built-in server (the port comes from WEBHOOK_PORT in .env, default 9000):
//   php -S 0.0.0.0:9000 src/webhook.php

require_once __DIR__ . '/Config.php';
require_once __DIR__ . '/Fluxa.php';

const MAX_SKEW_SECONDS = 300;

function respond(int $status, string $text): void
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    echo $text;
}

// Log through error_log(), never echo — echo would write into the HTTP response body.
// Under a web SAPI the STDOUT/STDERR constants do not exist — they are CLI-only, so
// fwrite(STDERR, ...) is a fatal here — and error_log() is the portable way out: it
// reaches the terminal under `php -S` and the fpm error log if this is deployed behind
// php-fpm/nginx instead.
function logLine(string $text): void
{
    error_log($text);
}

// Delivery is at-least-once: the same event can arrive more than once, so processing MUST be
// idempotent.
//
// The key MUST include refunded_amount. (event, order_id) alone is NOT unique: a single order
// can be partially refunded more than once, and each refund fires its own payment.refunded.
// Deduplicating on just that pair drops the second partial refund as a "duplicate" and returns
// 2xx — fluxa then records the delivery as successful and never retries. The customer is
// under-refunded and nothing errors anywhere in the chain.
// refunded_amount is cumulative and strictly increasing, so it separates a redelivery of the
// same event (same value -> deduplicate) from a genuinely new partial refund (higher value ->
// process). payment.succeeded / payment.failed carry no refunded_amount, so for them the key
// degrades to (event, order_id), which is correct for those.
//
// In a real integration this belongs in a database unique constraint (a unique index on
// order_id + event + refunded_amount); the file marker below is a demo stand-in.
// See ../../spec/SIGNING.md §3.1.
//
// PHP is shared-nothing: `php -S` re-executes this script from scratch for every request, so
// an in-process array — what the Node demo can use, being one long-lived process — would
// always start empty and dedupe nothing. The marker has to outlive the request, which is why
// this uses the filesystem. fopen(..., 'x') is O_CREAT|O_EXCL: an atomic create-if-absent, so
// two concurrent deliveries of the same event cannot both win.
function dedupeKey(array $evt): string
{
    return "{$evt['event']}:{$evt['order_id']}:" . ($evt['refunded_amount'] ?? '');
}

function claimEvent(string $key): bool
{
    $dir = sys_get_temp_dir() . '/fluxa-demo-webhook';
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    $marker = $dir . '/' . hash('sha256', $key) . '.marker';
    $fh = @fopen($marker, 'x');
    if ($fh === false) {
        return false; // already processed
    }
    fwrite($fh, $key . "\n");
    fclose($fh);

    return true;
}

function handle(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        respond(405, 'only POST');

        return;
    }

    // The signature MUST be verified against the raw received bytes: deserializing and
    // re-serializing changes the bytes and the signature will no longer match. php://input is
    // the exact body as received.
    $rawBody = (string) file_get_contents('php://input');
    $event = (string) ($_SERVER['HTTP_X_FLUXA_EVENT'] ?? '');
    $ts = (string) ($_SERVER['HTTP_X_FLUXA_TIMESTAMP'] ?? '');
    $sig = (string) ($_SERVER['HTTP_X_FLUXA_SIGNATURE'] ?? '');
    $encryption = (string) ($_SERVER['HTTP_X_FLUXA_ENCRYPTION'] ?? '');

    if (!Fluxa::verifyWebhook(Config::webhookSecret(), $ts, $rawBody, $sig)) {
        logLine("✗ Signature verification failed, event={$event} — rejected");
        respond(401, 'bad signature');

        return;
    }

    // Check the timestamp only after the signature passes, to limit the replay window.
    if (!ctype_digit($ts) || abs(time() - (int) $ts) > MAX_SKEW_SECONDS) {
        logLine("✗ Timestamp outside the allowed window, event={$event} — rejected");
        respond(401, 'stale timestamp');

        return;
    }

    // Verify first, then decrypt: the signature covers the envelope body as it was sent.
    $payload = $rawBody;
    if ($encryption === 'A256GCM') {
        try {
            $payload = Fluxa::decryptWebhook(Config::webhookSecret(), $rawBody);
            logLine("  (payload was an AES-256-GCM encrypted envelope; decrypted)");
        } catch (RuntimeException $e) {
            logLine("✗ Decryption failed: {$e->getMessage()}");
            respond(400, 'bad envelope');

            return;
        }
    }

    try {
        $evt = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        respond(400, 'bad json');

        return;
    }

    $key = dedupeKey($evt);
    if (!claimEvent($key)) {
        // Redelivery: already processed, so return 2xx without shipping goods or crediting
        // the account a second time.
        logLine("↺ Duplicate delivery ignored {$key}");
        respond(200, 'ok (duplicate)');

        return;
    }

    logLine("✓ {$evt['event']}  order={$evt['order_id']}  merchant_order={$evt['merchant_order_id']}");
    logLine("  {$evt['amount']} {$evt['currency']}  status={$evt['status']}  channel={$evt['channel']}");

    if ($evt['is_test'] ?? false) {
        // Test-key orders fire real webhooks so merchants can exercise the integration, but
        // no real money moved.
        logLine("  ⚠ is_test=true: this is a test order — do not actually ship goods.");
    }

    switch ($evt['event']) {
        case 'payment.succeeded':
            if ($evt['is_test'] ?? false) {
                break;
            }
            logLine("  → Ship goods / grant entitlements here (treat amounts as decimal strings, never floats)");
            break;
        case 'payment.failed':
            logLine("  → Mark the order failed here");
            break;
        case 'payment.refunded':
            // refunded_amount is the CUMULATIVE refunded total, not this event's refund;
            // $evt['amount'] is the ORDER TOTAL — computing a refund from it reads "1
            // refunded on a 1000 order" as "1000 refunded".
            //
            // Move your recorded total FORWARD ONLY — never add, and never blindly assign.
            // Delivery is at-least-once and arrival order is not guaranteed: deliveries are
            // not serialized per order, and a failed delivery is retried after a backoff, so
            // the event carrying 30 can land AFTER the one carrying 50. Assigning would
            // regress your total from 50 back to 30 and under-refund the customer; adding
            // would over-refund on a redelivery. Taking the max is both idempotent
            // (redelivery) and order-safe (reordering). Compare as decimals, not floats and
            // not strings. See ../../spec/SIGNING.md §3.1.
            $refunded = $evt['refunded_amount'] ?? '0';
            logLine("  → Refunded so far {$refunded} of order total {$evt['amount']} {$evt['currency']}"
                . " (status={$evt['status']}; partially_refunded means more may follow)");
            logLine('  → Advance your recorded refunded total to max(recorded, refunded_amount)'
                . ' — never assign blindly, and never add');
            break;
    }

    // Return 2xx quickly; anything else is retried by fluxa with exponential backoff, up to 8
    // attempts.
    respond(200, 'ok');
}

handle();
