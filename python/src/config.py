# Loads the shared ../../.env so every language demo is driven by one file.
# Real process env wins over .env, so `FLUXA_CHANNEL=stripe python3 src/charge.py` works.
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ENV_PATH = os.path.normpath(os.path.join(_HERE, "..", "..", ".env"))


def _parse_env(text):
    out = {}
    for line in text.split("\n"):
        t = line.strip()
        if not t or t.startswith("#"):
            continue
        eq = t.find("=")
        if eq < 0:
            continue
        key = t[:eq].strip()
        val = t[eq + 1 :].strip()
        if len(val) >= 2 and (
            (val.startswith('"') and val.endswith('"'))
            or (val.startswith("'") and val.endswith("'"))
        ):
            val = val[1:-1]
        out[key] = val
    return out


try:
    with open(_ENV_PATH, "r", encoding="utf-8") as f:
        _file_env = _parse_env(f.read())
except OSError:
    print(
        "{} not found — run cp .env.example .env in the repo root and fill in your keys.".format(_ENV_PATH),
        file=sys.stderr,
    )
    sys.exit(1)


def _get(key, fallback=None):
    # None-coalescing (not truthiness): an explicitly empty process env var still wins,
    # matching the JS `process.env[k] ?? fileEnv[k] ?? fallback`.
    val = os.environ.get(key)
    if val is None:
        val = _file_env.get(key)
    if val is None:
        val = fallback
    return val


def _required(key):
    val = _get(key)
    if not val or val.endswith("replace_me"):
        print(
            "{} is not filled in in .env (current value: {}).".format(key, val if val else "unset"),
            file=sys.stderr,
        )
        sys.exit(1)
    return val


class _Config:
    def __init__(self):
        self.base_url = _get("FLUXA_BASE_URL", "http://localhost:8090").rstrip("/")
        self.channel = _get("FLUXA_CHANNEL", "mock")
        self.currency = _get("FLUXA_CURRENCY", "USD")
        self.amount = _get("FLUXA_AMOUNT", "9.99")
        self.webhook_port = int(_get("WEBHOOK_PORT", "9000"))

    # Secrets are lazy properties: the webhook receiver only needs webhook_secret and
    # should not refuse to start just because FLUXA_KEY_ID is unset (and vice versa).
    @property
    def key_id(self):
        return _required("FLUXA_KEY_ID")

    @property
    def secret(self):
        return _required("FLUXA_SECRET")

    @property
    def webhook_secret(self):
        return _required("FLUXA_WEBHOOK_SECRET")


config = _Config()
