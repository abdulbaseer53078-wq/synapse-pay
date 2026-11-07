"""Operator commands. Run from backend/ with DATABASE_URL set:

    python -m app.cli create-merchant     # sandbox merchant: prints merchant_id, secret key, webhook secret
    python -m app.cli deliver-webhooks    # deliver due webhooks once
"""
import json
import os
import sys

from psycopg_pool import ConnectionPool

from app.infrastructure.postgres_api_keys import create_merchant
from app.infrastructure.webhook_outbox import WebhookDispatcher


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in ("create-merchant", "deliver-webhooks"):
        print(__doc__)
        return 2
    with ConnectionPool(os.environ["DATABASE_URL"], min_size=1, max_size=2) as pool:
        if argv[0] == "create-merchant":
            print(json.dumps(create_merchant(pool), indent=2))
            print("Keep the secret key and webhook secret safe: they are shown only now.", file=sys.stderr)
        else:
            allow_insecure = os.environ.get("ALLOW_INSECURE_WEBHOOKS") == "1"
            print(f"delivered {WebhookDispatcher(pool, allow_insecure).deliver_due()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
