// Webhook receiver demo: verify signature -> decrypt (if enabled) -> process idempotently
// -> return 2xx.
//
//   cargo run --bin webhook

use std::collections::HashSet;
use std::fmt::Display;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use tiny_http::{Header, Method, Request, Response, Server};

use fluxa::{decrypt_webhook, verify_webhook, Event};

const MAX_SKEW_SECONDS: i64 = 300;
const MAX_BODY_BYTES: u64 = 1 << 20;

fn main() {
    let cfg = fluxa::config::load().unwrap_or_else(fatal);
    cfg.require_webhook_secret().unwrap_or_else(fatal);

    let addr = format!("0.0.0.0:{}", cfg.webhook_port);
    let server =
        Server::http(&addr).unwrap_or_else(|e| fatal(format!("failed to listen on {addr}: {e}")));

    // Deduplicate using event_id from the verified, decrypted body; HTTP headers are not signed. Production must commit the event_id unique row and business changes in one transaction before returning 2xx. The local store here only demonstrates duplicate detection.
    let mut processed: HashSet<String> = HashSet::new();

    println!(
        "fluxa webhook receiver listening on http://localhost:{}",
        cfg.webhook_port
    );
    println!(
        "Point your portal callback URL here. It must be reachable from the internet, so for\n\
         local testing expose it with a tunnel such as ngrok and register that URL."
    );

    for request in server.incoming_requests() {
        handle(request, &cfg.webhook_secret, &mut processed);
    }
}

fn handle(mut request: Request, secret: &str, processed: &mut HashSet<String>) {
    if *request.method() != Method::Post {
        respond(request, 405, "only POST");
        return;
    }

    // The signature MUST be verified against the raw received bytes: deserializing and
    // re-serializing changes the bytes and the signature will no longer match. So the body
    // is read whole first, and every kind of decoding happens only after verification.
    let mut raw_body = Vec::new();
    if request
        .as_reader()
        .take(MAX_BODY_BYTES + 1)
        .read_to_end(&mut raw_body)
        .is_err()
    {
        respond(request, 400, "cannot read body");
        return;
    }
    if raw_body.len() as u64 > MAX_BODY_BYTES {
        respond(request, 413, "body too large");
        return;
    }

    let event_hdr = header(&request, "X-Fluxa-Event");
    let ts = header(&request, "X-Fluxa-Timestamp");
    let sig = header(&request, "X-Fluxa-Signature");
    let encryption = header(&request, "X-Fluxa-Encryption");

    if !verify_webhook(secret, &ts, &raw_body, &sig) {
        eprintln!("✗ Signature verification failed, event={event_hdr} — rejected");
        respond(request, 401, "bad signature");
        return;
    }

    // Check the timestamp only after the signature passes, to limit the replay window.
    match ts.parse::<i64>() {
        Ok(sent) if (now_seconds() - sent).abs() <= MAX_SKEW_SECONDS => {}
        Ok(sent) => {
            eprintln!(
                "✗ Timestamp outside the allowed window ({}s), event={event_hdr} — rejected",
                (now_seconds() - sent).abs()
            );
            respond(request, 401, "stale timestamp");
            return;
        }
        Err(_) => {
            eprintln!("✗ Timestamp is not a valid integer, event={event_hdr} — rejected");
            respond(request, 401, "stale timestamp");
            return;
        }
    }

    // Verify first, then decrypt: the signature covers the envelope body as it was sent.
    let payload = if encryption == "A256GCM" {
        match decrypt_webhook(secret, &raw_body) {
            Ok(plain) => {
                println!("  (payload was an AES-256-GCM encrypted envelope; decrypted)");
                plain
            }
            Err(e) => {
                eprintln!("✗ Decryption failed: {e}");
                respond(request, 400, "bad envelope");
                return;
            }
        }
    } else {
        raw_body
    };

    let Ok(evt) = serde_json::from_slice::<Event>(&payload) else {
        respond(request, 400, "bad json");
        return;
    };

    let key = evt.dedupe_key();
    if key.is_empty() {
        respond(request, 400, "missing or invalid event_id");
        return;
    }
    if !processed.insert(key.clone()) {
        // Redelivery: already processed, so return 2xx immediately without shipping goods
        // or crediting the account a second time.
        println!("↺ Duplicate delivery ignored {key}");
        respond(request, 200, "ok (duplicate)");
        return;
    }

    println!(
        "✓ {}  order={}  merchant_order={}",
        evt.event, evt.order_id, evt.merchant_order_id
    );
    println!(
        "  {} {}  status={}  channel={}",
        evt.amount, evt.currency, evt.status, evt.channel
    );
    if evt.is_test {
        // Test-key orders fire real webhooks so merchants can exercise the integration,
        // but no real money moved.
        println!("  ⚠ is_test=true: this is a test order — do not actually ship goods.");
    }

    match evt.event.as_str() {
        "payment.succeeded" => {
            if !evt.is_test && evt.settle_on_received {
                println!("  → Advance credited gross to max(recorded, received_amount) atomically and apply only the positive delta; never add deposit_amount separately or fulfill twice. {}", evt.received_amount);
            } else if !evt.is_test {
                println!(
                    "  → Ship goods / grant entitlements here (treat amounts as decimal strings, never floats)"
                );
            }
        }
        "payment.additional_received" => {
            if !evt.is_test { println!("  → Advance credited gross to max(recorded, received_amount) atomically and apply only the positive delta; never add deposit_amount separately or fulfill twice. {}", evt.received_amount); }
        }
        "payment.pending" => println!("  → Show the latest voucher/payment_expires_at only while the order is pending; do not fulfill."),
        "order.created" => println!("  → Record the pending order; do not fulfill."),
        "order.expired" => println!("  → Close the checkout and hide payment instructions; reconcile current order state before applying late events."),
        "order.canceled" => println!("  → Close the checkout and hide payment instructions; reconcile current order state before applying late events."),
        "payment.dispute_created" => println!("  → Track dispute_id and is_inquiry/escalated; a late creation must not overwrite a closed dispute. No balance change here."),
        "payment.dispute_closed" => println!("  → Track outcome by dispute_id; corrected=true can replace lost with won. No balance change here."),
        "settlement.completed" => println!("  → Record settlement_tx as a receipt of merchant settlement; do not fulfill or credit the customer again."),
        "subscription.charged" => println!("  → Record the subscription update; do not duplicate fulfillment from payment.succeeded."),
        "subscription.payment_failed" => println!("  → Record the failed subscription payment; reconcile subscription state."),
        "subscription.completed" => println!("  → Record subscription completion; do not fulfill again."),
        "payment.failed" => println!("  → Mark the order failed here"),
        "payment.refunded" => {
            // refunded_amount is the CUMULATIVE refunded total, not this event's refund.
            // evt.amount is the ORDER TOTAL — computing a refund from it reads "1 refunded
            // on a 1000 order" as "1000 refunded".
            //
            // Move your recorded total FORWARD ONLY — never add, and never blindly assign.
            // Delivery is at-least-once and arrival order is not guaranteed: deliveries are
            // not serialized per order, and a failed delivery is retried after a backoff, so
            // the event carrying 30 can land AFTER the one carrying 50. Assigning would
            // regress your total from 50 back to 30 and under-refund the customer; adding
            // would over-refund on a redelivery. Taking the max is both idempotent
            // (redelivery) and order-safe (reordering). Compare as decimals, not floats and
            // not strings. See ../../spec/SIGNING.md §3.1.
            println!(
                "  → Refunded so far {} of order total {} {} (status={}; partially_refunded means more may follow)",
                evt.refunded_amount.as_deref().unwrap_or("0"),
                evt.amount,
                evt.currency,
                evt.status
            );
            println!(
                "  → Advance your recorded refunded total to max(recorded, refunded_amount) — never assign blindly, and never add"
            );
        }
        _ => {}
    }

    // Return 2xx quickly; anything else is retried by fluxa with exponential backoff, up to
    // 8 attempts.
    respond(request, 200, "ok");
}

/// header reads one request header, returning an empty string when absent. HTTP header
/// names are case-insensitive, which `equiv` already handles.
fn header(request: &Request, name: &'static str) -> String {
    request
        .headers()
        .iter()
        .find(|h: &&Header| h.field.equiv(name))
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_default()
}

fn respond(request: Request, status: u16, body: &str) {
    let response = Response::from_string(body).with_status_code(status);
    if let Err(e) = request.respond(response) {
        eprintln!("✗ Failed to send response: {e}");
    }
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

fn fatal<T>(err: impl Display) -> T {
    eprintln!("{err}");
    std::process::exit(1);
}
