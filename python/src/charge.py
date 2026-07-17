# Charge demo: create a charge, print the payer instruction, then read the order back.
#   python3 src/charge.py
import sys
import time

from config import config
from fluxa import create_charge, get_order


def main():
    merchant_order_id = sys.argv[1] if len(sys.argv) > 1 else "demo-{}".format(int(time.time() * 1000))

    charge = {
        # merchant_order_id is the idempotency key: re-sending the same value returns the
        # same order (idempotent: true) instead of creating a second charge.
        "merchant_order_id": merchant_order_id,
        "amount": config.amount,  # decimal string — never a float
        "currency": config.currency,
        "channel": config.channel,
        "subject": "fluxa demo item",
        "description": "Created by fluxa-demo/python",
        "metadata": {"source": "fluxa-demo", "lang": "python"},
        "return_url": "https://example.com/pay/success",
        "cancel_url": "https://example.com/pay/cancel",
        "expires_in_seconds": 1800,
    }

    print("→ POST /api/v1/charges  (merchant_order_id={})".format(merchant_order_id))
    res = create_charge(config, charge)

    order = res["order"]
    payment = res["payment"]
    instruction = res["instruction"]

    print(
        "✓ Order created {}  status={}  {} {}".format(
            order["id"], order["status"], order["amount"], order["currency"]
        )
    )
    if res.get("idempotent"):
        print("  (idempotent hit: this merchant_order_id already existed — returning the original order)")
    print("  Channel payment={} channel={}".format(payment["id"], payment["channel_code"]))

    # instruction.type decides how to drive the payer.
    kind = instruction["type"]
    if kind == "redirect":
        print("\nPayment method: send the payer to the checkout page\n  {}".format(instruction["redirect_url"]))
    elif kind == "crypto_address":
        print(
            "\nPayment method: transfer to this address"
            "\n  Chain: {}  Asset: {}"
            "\n  Address: {}"
            "\n  Amount due: {}"
            "\n  Required confirmations: {}".format(
                instruction["chain"],
                instruction["asset"],
                instruction["deposit_address"],
                instruction["amount_due"],
                instruction["required_confirmations"],
            )
        )
    elif kind == "client_secret":
        print("\nPayment method: confirm client-side with client_secret\n  {}".format(instruction["client_secret"]))
    elif kind == "none":
        print("\nThis channel needs no payer action.")
    else:
        print("\nUnknown instruction.type={}: {}".format(kind, instruction))

    print("\n→ GET /api/v1/orders/{}".format(order["id"]))
    detail = get_order(config, order["id"])
    print("✓ Read back status={}".format(detail["order"]["status"]))
    print(
        "\nOnce the order is paid, fluxa POSTs payment.succeeded to the callback URL registered in the portal."
        "\nTo receive it locally: python3 src/webhook.py (your callback URL must be publicly reachable —"
        " use a tunnel such as ngrok)."
    )


if __name__ == "__main__":
    main()
