<?php

declare(strict_types=1);

// Known-answer tests: this implementation must reproduce ../../spec/vectors.json byte for
// byte. Those vectors are generated from fluxa's actual server-side signing code, which makes
// them the single criterion for a correct port — and checking them needs no running server
// and no credentials.
//
//   php test/vectors_test.php
//
// Besides the vectors, this file also carries the webhook idempotency-key regression tests
// (see the "Idempotency-key regression tests" section). They check no vector, but this demo
// has exactly one test entry point, so putting them here is what gets them run by
// ./verify-all.sh php.
//
// Plain assertions, no PHPUnit: on failure it prints actual/expected and exits non-zero.

require_once __DIR__ . '/../src/Fluxa.php';

final class T
{
    public static int $passed = 0;
    public static array $failures = [];
    private static string $group = '';

    // section mirrors the Node demo's `await t.test(name, fn)`: a throw inside one case
    // is recorded as that case's failure and the remaining cases still run, instead of a
    // fatal that aborts the file and hides every later assertion.
    public static function section(string $name, callable $body): void
    {
        self::$group = $name;
        try {
            $body();
        } catch (Throwable $e) {
            self::$failures[] = sprintf('%s: unexpectedly threw %s: %s', $name, $e::class, $e->getMessage());
        }
    }

    public static function eq(mixed $actual, mixed $expected, string $msg): void
    {
        if ($actual === $expected) {
            self::$passed++;

            return;
        }
        self::$failures[] = sprintf(
            "%s: %s\n      actual:   %s\n      expected: %s",
            self::$group,
            $msg,
            self::show($actual),
            self::show($expected),
        );
    }

    public static function ok(bool $cond, string $msg): void
    {
        if ($cond) {
            self::$passed++;

            return;
        }
        self::$failures[] = sprintf('%s: %s', self::$group, $msg);
    }

    public static function throws(callable $fn, string $msg): void
    {
        try {
            $fn();
        } catch (Throwable) {
            self::$passed++;

            return;
        }
        self::$failures[] = sprintf('%s: %s (nothing was thrown)', self::$group, $msg);
    }

    private static function show(mixed $v): string
    {
        if (is_string($v)) {
            return '"' . str_replace("\n", '\n', $v) . '"';
        }

        return var_export($v, true);
    }
}

$vectors = json_decode(
    (string) file_get_contents(__DIR__ . '/../../spec/vectors.json'),
    true,
    512,
    JSON_THROW_ON_ERROR,
);

// ---- Request signing vectors ----
foreach ($vectors['requests'] as $v) {
    T::section("request signing vectors/{$v['name']}", function () use ($v) {
        $canon = Fluxa::canonical($v['method'], $v['path'], $v['raw_query'], $v['timestamp'], $v['body']);
        T::eq($canon, $v['canonical'], 'canonical string mismatch');
        T::eq(Fluxa::sign($v['secret'], $canon), $v['signature'], 'signature mismatch');
    });
}

// ---- With no query, line 3 of the canonical must be an empty line (5 lines, not 4) ----
T::section('canonical shape with no query', function () {
    $canon = Fluxa::canonical('POST', '/api/v1/charges', '', '1750000000', '{}');
    $lines = explode("\n", $canon);
    T::eq(count($lines), 5, 'canonical must be 5 lines');
    T::eq($lines[2], '', 'line 3 (CANONICAL_QUERY) must be the empty string');
});

// ---- Query order does not change the signature, but tampering does ----
T::section('query sorting and tampering', function () {
    $a = Fluxa::canonical('GET', '/api/v1/orders', 'status=paid&limit=10', '1750000000', '');
    $b = Fluxa::canonical('GET', '/api/v1/orders', 'limit=10&status=paid', '1750000000', '');
    T::eq($a, $b, 'different param order must give the same canonical');
    $tampered = Fluxa::canonical('GET', '/api/v1/orders', 'status=failed&limit=10', '1750000000', '');
    T::ok($a !== $tampered, 'tampering with a param value must change the canonical');
    $dropped = Fluxa::canonical('GET', '/api/v1/orders', '', '1750000000', '');
    T::ok($a !== $dropped, 'dropping the query must change the canonical');
});

// Fragments must sort in UTF-8 byte order to match the server. PHP's default SORT_REGULAR
// would compare numeric-looking fragments numerically, so this pins SORT_STRING's byte-order
// behaviour.
T::section('query fragments sort in byte order', function () {
    $byteOrder = Fluxa::canonical('GET', '/x', "\u{FFFD}=a&\u{10000}=b", '1750000000', '');
    T::eq(
        explode("\n", $byteOrder)[2],
        "\u{FFFD}=a&\u{10000}=b",
        'U+FFFD (EF BF BD) must sort before U+10000 (F0 90 80 80)',
    );
});

// ---- signedHeaders folds a query in the path into the signature ----
T::section('signedHeaders', function () {
    $h = Fluxa::signedHeaders('pk_x', 'sk_x', 'GET', '/api/v1/orders?status=paid&limit=10', '', 1750000000);
    $want = Fluxa::sign('sk_x', Fluxa::canonical('GET', '/api/v1/orders', 'status=paid&limit=10', '1750000000', ''));
    T::eq($h['X-Signature'], $want, 'a query in the path must be folded into the signature');
    T::eq($h['X-Timestamp'], '1750000000', 'X-Timestamp must be the seconds value passed in');
    T::eq($h['X-Api-Key'], 'pk_x', 'X-Api-Key must be the key_id');
});

// ---- Webhook signature vectors ----
foreach ($vectors['webhooks'] as $w) {
    T::section("webhook signature vectors/{$w['name']}", function () use ($w) {
        T::eq(Fluxa::sign($w['secret'], $w['signed_raw']), $w['signature'], 'signature mismatch');
        T::ok(Fluxa::verifyWebhook($w['secret'], $w['timestamp'], $w['body'], $w['signature']), 'should verify');
        T::ok(
            !Fluxa::verifyWebhook($w['secret'], $w['timestamp'], $w['body'] . 'x', $w['signature']),
            'a tampered body must be rejected',
        );
        T::ok(
            !Fluxa::verifyWebhook('wrong_secret', $w['timestamp'], $w['body'], $w['signature']),
            'a wrong secret must be rejected',
        );
        T::ok(
            !Fluxa::verifyWebhook($w['secret'], $w['timestamp'], $w['body'], ''),
            'an empty signature must be rejected',
        );
    });
}

// ---- AES-256-GCM envelope decryption vectors ----
foreach ($vectors['envelopes'] as $e) {
    T::section("envelope decryption vectors/{$e['name']}", function () use ($e) {
        T::eq(Fluxa::decryptWebhook($e['secret'], $e['envelope']), $e['plaintext'], 'plaintext mismatch');
        T::throws(fn () => Fluxa::decryptWebhook('wrong_secret', $e['envelope']), 'a wrong secret must fail to decrypt');
    });
}

// ---- Idempotency-key regression tests ----
//
// fluxa allows an order to be partially refunded more than once — further refunds are allowed
// until refunded_amount reaches the order total — and every refund fires its own
// payment.refunded event. So (event, order_id) is NOT unique.
//
// Deduplicating on just (event, order_id) silently drops the second partial refund and returns
// 2xx, so fluxa records the delivery as successful and never retries. The customer is
// under-refunded and nothing errors anywhere in the chain. The sections below pin the correct
// behaviour. See ../../spec/SIGNING.md §3.1.

// Kept in sync with dedupeKey in src/webhook.php. It is duplicated here rather than required:
// src/webhook.php calls handle() at the bottom, so merely loading it would read php://input
// and emit a response.
$dedupeKey = fn (array $evt): string => "{$evt['event']}:{$evt['order_id']}:" . ($evt['refunded_amount'] ?? '');

// The tempting-but-wrong key these tests falsify. Kept so nobody "simplifies" back to it.
$brokenKey = fn (array $evt): string => "{$evt['event']}:{$evt['order_id']}";

$refund = fn (string $cumulative, string $status = 'partially_refunded'): array => [
    'event' => 'payment.refunded',
    'order_id' => 'ord_X',
    'merchant_order_id' => 'o-1',
    'amount' => '1000.00',
    'refunded_amount' => $cumulative,
    'currency' => 'USD',
    'status' => $status,
    'channel' => 'mock',
];

T::section('dedupe key/two partial refunds must have different keys', function () use ($dedupeKey, $brokenKey, $refund) {
    $first = $refund('30.00');
    $second = $refund('50.00'); // cumulative: 30 + 20
    T::ok(
        $dedupeKey($first) !== $dedupeKey($second),
        'two partial refunds were judged the same event — the second would be dropped',
    );

    // Pins the trap itself: the naive key really does collide on these two.
    T::eq($brokenKey($first), $brokenKey($second), 'premise check: the (event, order_id) key does collide here');
});

T::section('dedupe key/a redelivery of the same event must hit the same key', function () use ($dedupeKey, $refund) {
    $evt = $refund('30.00');
    $redelivery = $evt; // fluxa redelivers the identical payload
    T::eq($dedupeKey($evt), $dedupeKey($redelivery), 'a redelivery must be deduplicated');
});

T::section('dedupe key/a full refund differs from an earlier partial refund', function () use ($dedupeKey, $refund) {
    T::ok(
        $dedupeKey($refund('30.00')) !== $dedupeKey($refund('1000.00', 'refunded')),
        'a full refund must be distinguishable from an earlier partial refund',
    );
});

T::section('dedupe key/succeeded has no refunded_amount, so the key degrades', function () use ($dedupeKey) {
    $ok = ['event' => 'payment.succeeded', 'order_id' => 'ord_X', 'status' => 'paid'];
    T::eq($dedupeKey($ok), 'payment.succeeded:ord_X:', 'an absent field must degrade to a trailing empty part');
    $redelivery = $ok;
    T::eq($dedupeKey($ok), $dedupeKey($redelivery), 'a redelivery must be deduplicated');
});

T::section('dedupe key/succeeded and refunded are different keys', function () use ($dedupeKey, $refund) {
    $ok = ['event' => 'payment.succeeded', 'order_id' => 'ord_X'];
    T::ok($dedupeKey($ok) !== $dedupeKey($refund('30.00')), 'different events must have different keys');
});

// The real-world scenario: a 1000 order refunded 30, then 20 (cumulative 50).
T::section('dedupe key/end to end: both partial refunds must be processed', function () use ($dedupeKey, $refund) {
    $processed = [];
    $accept = function (array $evt) use (&$processed, $dedupeKey): bool {
        $k = $dedupeKey($evt);
        if (isset($processed[$k])) {
            return false;
        }
        $processed[$k] = true;

        return true;
    };

    T::eq($accept($refund('30.00')), true, 'the first refund must be processed');
    T::eq($accept($refund('30.00')), false, 'a redelivery of the first must be deduplicated');
    T::eq($accept($refund('50.00')), true, 'the second partial refund must be processed — the one the naive key drops');
    T::eq($accept($refund('50.00')), false, 'a redelivery of the second must be deduplicated');
});

// ---- Ordering ----
//
// at-least-once says nothing about ORDER. Deliveries are not serialized per order, and a
// failed delivery is retried after a backoff — so the event carrying the 30 can land after the
// one carrying 50.
//
// Dedupe alone does not save you here: a late 30 is a DIFFERENT key from 50, so it is
// correctly not a duplicate — it gets processed, and a blind assignment regresses the recorded
// total. Advancing to max(recorded, incoming) is idempotent AND order-safe.

// Cumulative totals are decimal strings. Comparing them as floats is the very bug the rest of
// this repo warns about, and comparing them as plain strings is worse: "9.90" > "10.00"
// lexicographically. So compare integer and fraction parts separately, zero-padded. This is
// hand-rolled rather than bccomp() because bcmath is not built into the stock php image.
$decimalGreater = function (string $a, string $b): bool {
    [$ai, $af] = array_pad(explode('.', $a, 2), 2, '');
    [$bi, $bf] = array_pad(explode('.', $b, 2), 2, '');

    if (str_pad($ai, 20, '0', STR_PAD_LEFT) !== str_pad($bi, 20, '0', STR_PAD_LEFT)) {
        return str_pad($ai, 20, '0', STR_PAD_LEFT) > str_pad($bi, 20, '0', STR_PAD_LEFT);
    }
    $n = max(strlen($af), strlen($bf));

    return str_pad($af, $n, '0') > str_pad($bf, $n, '0');
};

// Move the recorded total forward only.
$advance = fn (string $recorded, string $incoming): string => $decimalGreater($incoming, $recorded)
    ? $incoming
    : $recorded;

T::section('ordering/out-of-order refunds must not regress the recorded total', function () use ($advance, $refund) {
    $recorded = '0';

    // The 50 lands first (the 30's delivery failed and is still backing off).
    $recorded = $advance($recorded, $refund('50.00')['refunded_amount']);
    T::eq($recorded, '50.00', 'the 50 must be recorded');

    // The 30 arrives late on retry. It is NOT a duplicate — different key — so it is
    // processed. A blind assignment would drop the total back to 30.
    $recorded = $advance($recorded, $refund('30.00')['refunded_amount']);
    T::eq($recorded, '50.00', 'a late, lower cumulative value must not move the total backwards');
});

T::section('ordering/in-order refunds still advance normally', function () use ($advance) {
    $recorded = '0';
    $recorded = $advance($recorded, '30.00');
    T::eq($recorded, '30.00', 'the first refund must advance the total');
    $recorded = $advance($recorded, '50.00');
    T::eq($recorded, '50.00', 'the second refund must advance the total');
    $recorded = $advance($recorded, '1000.00'); // fully refunded
    T::eq($recorded, '1000.00', 'a full refund must advance the total');
});

T::section('ordering/a redelivery of the same cumulative value is a no-op', function () use ($advance) {
    T::eq($advance('50.00', '50.00'), '50.00', 'a redelivery must not change the total');
});

T::section('ordering/comparison is by decimal, not float or string', function () use ($decimalGreater) {
    T::ok($decimalGreater('50.00', '30.00'), '50.00 must be greater than 30.00');
    T::ok(!$decimalGreater('30.00', '50.00'), '30.00 must not be greater than 50.00');
    // A naive string compare gets this wrong: "9.90" > "10.00" lexicographically.
    T::ok($decimalGreater('10.00', '9.90'), '10.00 must be greater than 9.90');
    T::ok(!$decimalGreater('9.90', '10.00'), '9.90 must not be greater than 10.00');
    T::ok(!$decimalGreater('50.00', '50.00'), 'equal is not greater');
});

// ---- Summary ----
$failed = count(T::$failures);
if ($failed > 0) {
    fwrite(STDERR, "\n✗ {$failed} failure(s):\n");
    foreach (T::$failures as $f) {
        fwrite(STDERR, "  - {$f}\n");
    }
    $total = T::$passed + $failed;
    fwrite(STDERR, "\nPassed " . T::$passed . "/{$total}\n");
    exit(1);
}

$total = T::$passed;
fwrite(STDOUT, "✓ All {$total}/{$total} passed  (byte-for-byte against spec/vectors.json)\n");
exit(0);
