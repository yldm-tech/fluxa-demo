// Loads the shared ../../.env so every language demo is driven by one file.
// Real process env wins over .env, so `FLUXA_CHANNEL=stripe npm run charge` works.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const envPath = join(here, "..", "..", ".env");

function parseEnv(text) {
  const out = {};
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const eq = t.indexOf("=");
    if (eq < 0) continue;
    const key = t.slice(0, eq).trim();
    let val = t.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    out[key] = val;
  }
  return out;
}

let fileEnv = {};
try {
  fileEnv = parseEnv(readFileSync(envPath, "utf8"));
} catch {
  console.error(`${envPath} not found — run cp .env.example .env in the repo root and fill in your keys.`);
  process.exit(1);
}

const get = (k, fallback) => process.env[k] ?? fileEnv[k] ?? fallback;

function required(k) {
  const v = get(k);
  if (!v || v.endsWith("replace_me")) {
    console.error(`${k} is not filled in in .env (current value: ${v ?? "unset"}).`);
    process.exit(1);
  }
  return v;
}

export const config = {
  baseUrl: (get("FLUXA_BASE_URL", "http://localhost:8090")).replace(/\/+$/, ""),
  get keyId() { return required("FLUXA_KEY_ID"); },
  get secret() { return required("FLUXA_SECRET"); },
  get webhookSecret() { return required("FLUXA_WEBHOOK_SECRET"); },
  channel: get("FLUXA_CHANNEL", "mock"),
  currency: get("FLUXA_CURRENCY", "USD"),
  amount: get("FLUXA_AMOUNT", "9.99"),
  webhookPort: Number(get("WEBHOOK_PORT", "9000")),
};
