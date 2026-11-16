<?php

declare(strict_types=1);

// Webhook receiver demo: verify signature -> decrypt (if enabled) -> process idempotently
// -> return 2xx.
// Runs under PHP's built-in server (the port comes from WEBHOOK_PORT in .env, default 9000):
//   php -S 0.0.0.0:9000 src/webhook.php

require_once __DIR__ . '/Config.php';
require_once __DIR__ . '/Fluxa.php';

const MAX_SKEW_SECONDS = 300;
const MAX_BODY_BYTES = 1 << 20;

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

// Deduplicate using event_id from the verified, decrypted body; HTTP headers are not signed. Production must commit the event_id unique row and business changes in one transaction before returning 2xx. The local store here only demonstrates duplicate detection.
// PHP requests do not share memory: claimEvent uses an atomic file marker for this demo only.

// readBody drains php://input with a hard cap, matching the 1 MiB limit and 413 response the
// other language demos enforce. Returns null when the body exceeds MAX_BODY_BYTES. post_max_size
// would backstop this eventually (with an empty php://input, not a 413), so the cap is applied
// here explicitly to keep the observable behaviour in step with the other receivers.
function readBody(): ?string
{
    $in = fopen('php://input', 'rb');
    if ($in === false) {
        return '';
    }
    $body = '';
    while (!feof($in)) {
        $chunk = fread($in, 8192);
        if ($chunk === false) {
            break;
        }
        $body .= $chunk;
        if (strlen($body) > MAX_BODY_BYTES) {
            fclose($in);

            return null;
        }
    }
    fclose($in);

    return $body;
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
    $rawBody = readBody();
    if ($rawBody === null) {
        respond(413, 'body too large');

        return;
    }
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

    $key = Fluxa::dedupeKey($evt);
    if ($key === '') {
        respond(400, 'missing or invalid event_id');
        return;
    }
    if (!claimEvent($key)) {
        // Redelivery: already processed, so return 2xx without shipping goods or crediting
        // the account a second time.
        logLine("↺ Duplicate delivery ignored {$key}");
        respond(200, 'ok (duplicate)');

        return;
    }

    logLine(sprintf('✓ %s event_id=%s order=%s merchant_order=%s', $evt['event'] ?? '', $key, $evt['order_id'] ?? '', $evt['merchant_order_id'] ?? ''));
    logLine(sprintf('  %s %s status=%s channel=%s', $evt['amount'] ?? '', $evt['currency'] ?? '', $evt['status'] ?? '', $evt['channel'] ?? ''));

    if ($evt['is_test'] ?? false) {
        // Test-key orders fire real webhooks so merchants can exercise the integration, but
        // no real money moved.
        logLine("  ⚠ is_test=true: this is a test order — do not actually ship goods.");
    }

    switch ($evt['event'] ?? '') {
        case 'payment.succeeded':
            if ($evt['is_test'] ?? false) {
                break;
            }
            if ($evt['settle_on_received'] ?? false) {
                logLine('  → Advance credited gross to max(recorded, received_amount) atomically and apply only the positive delta; never add deposit_amount separately or fulfill twice. ' . ($evt['received_amount'] ?? ''));
                break;
            }
            logLine("  → Ship goods / grant entitlements here (treat amounts as decimal strings, never floats)");
            break;
        case 'payment.additional_received':
            if (!($evt['is_test'] ?? false)) logLine('  → Advance credited gross to max(recorded, received_amount) atomically and apply only the positive delta; never add deposit_amount separately or fulfill twice. ' . ($evt['received_amount'] ?? ''));
            break;
        case 'payment.pending':
            logLine('  → Show the latest voucher/payment_expires_at only while the order is pending; do not fulfill.');
            break;
        case 'order.created':
            logLine('  → Record the pending order; do not fulfill.');
            break;
        case 'order.expired':
            logLine('  → Close the checkout and hide payment instructions; reconcile current order state before applying late events.');
            break;
        case 'order.canceled':
            logLine('  → Close the checkout and hide payment instructions; reconcile current order state before applying late events.');
            break;
        case 'payment.dispute_created':
            logLine('  → Track dispute_id and is_inquiry/escalated; a late creation must not overwrite a closed dispute. No balance change here.');
            break;
        case 'payment.dispute_closed':
            logLine('  → Track outcome by dispute_id; corrected=true can replace lost with won. No balance change here.');
            break;
        case 'settlement.completed':
            logLine('  → Record settlement_tx as a receipt of merchant settlement; do not fulfill or credit the customer again.');
            break;
        case 'subscription.charged':
            logLine('  → Record the subscription update; do not duplicate fulfillment from payment.succeeded.');
            break;
        case 'subscription.payment_failed':
            logLine('  → Record the failed subscription payment; reconcile subscription state.');
            break;
        case 'subscription.completed':
            logLine('  → Record subscription completion; do not fulfill again.');
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
