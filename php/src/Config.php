<?php

declare(strict_types=1);

// Loads the shared ../../.env so every language demo is driven by one file.
// Real process env wins over .env, so `FLUXA_CHANNEL=stripe php src/charge.php` works.

final class Config
{
    private static ?array $fileEnv = null;

    // The secrets are read through methods rather than resolved up front, mirroring the
    // Node demo's lazy getters: the webhook receiver must not die because FLUXA_KEY_ID
    // is unset, and charge must not die because the webhook secret is.
    public static function baseUrl(): string
    {
        return rtrim(self::get('FLUXA_BASE_URL', 'http://localhost:8090'), '/');
    }

    public static function keyId(): string
    {
        return self::required('FLUXA_KEY_ID');
    }

    public static function secret(): string
    {
        return self::required('FLUXA_SECRET');
    }

    public static function webhookSecret(): string
    {
        return self::required('FLUXA_WEBHOOK_SECRET');
    }

    public static function channel(): string
    {
        return self::get('FLUXA_CHANNEL', 'mock');
    }

    public static function currency(): string
    {
        return self::get('FLUXA_CURRENCY', 'USD');
    }

    public static function amount(): string
    {
        return self::get('FLUXA_AMOUNT', '9.99');
    }

    public static function webhookPort(): int
    {
        return (int) self::get('WEBHOOK_PORT', '9000');
    }

    private static function fileEnv(): array
    {
        if (self::$fileEnv !== null) {
            return self::$fileEnv;
        }
        $path = dirname(__DIR__, 2) . '/.env';
        $text = @file_get_contents($path);
        if ($text === false) {
            self::fatal("{$path} not found — run `cp .env.example .env` at the repo root and fill in your keys.");
        }
        self::$fileEnv = self::parseEnv($text);

        return self::$fileEnv;
    }

    private static function parseEnv(string $text): array
    {
        $out = [];
        foreach (explode("\n", $text) as $line) {
            $t = trim($line);
            if ($t === '' || str_starts_with($t, '#')) {
                continue;
            }
            $eq = strpos($t, '=');
            if ($eq === false) {
                continue;
            }
            $key = trim(substr($t, 0, $eq));
            $val = trim(substr($t, $eq + 1));
            if (
                (str_starts_with($val, '"') && str_ends_with($val, '"'))
                || (str_starts_with($val, "'") && str_ends_with($val, "'"))
            ) {
                $val = substr($val, 1, -1);
            }
            $out[$key] = $val;
        }

        return $out;
    }

    // getenv() returns false when a variable is unset but "" when it is set-but-empty.
    // Test for false explicitly: a `!$env` check would fall through to the .env file for
    // a deliberately-empty override, which is not what the other demos do.
    private static function get(string $k, ?string $fallback = null): ?string
    {
        // Resolve the file first even when the process env will win, so that a missing
        // .env is fatal for every key — the Node demo reads it eagerly at import, and a
        // per-key lazy read would make the error depend on which vars you happened to
        // override. It is parsed once and cached.
        $fileEnv = self::fileEnv();
        $env = getenv($k);
        if ($env !== false) {
            return $env;
        }

        return $fileEnv[$k] ?? $fallback;
    }

    private static function required(string $k): string
    {
        $v = self::get($k);
        if ($v === null || $v === '' || str_ends_with($v, 'replace_me')) {
            self::fatal(sprintf('%s is not filled in yet in .env (current value: %s).', $k, $v ?? 'unset'));
        }

        return $v;
    }

    // Config is shared by the CLI entrypoint and by webhook.php running under `php -S`,
    // and the STDERR constant only exists in the CLI SAPI — using it here would turn a
    // friendly "go fill in your .env" message into an uncaught fatal in the receiver.
    // The php://stderr wrapper works in both.
    private static function fatal(string $msg): never
    {
        $stderr = fopen('php://stderr', 'w');
        if ($stderr !== false) {
            fwrite($stderr, $msg . "\n");
            fclose($stderr);
        }
        exit(1);
    }
}
