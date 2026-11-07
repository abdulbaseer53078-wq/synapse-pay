import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

# shortcut: approved models and their hardware_id formats live in config; replace with the
# Step 26 certification registry (or manufacturer device manifests) when it exists.
DEFAULT_APPROVED_MODELS = {
    "PAX A920 Pro": r"PAX-A920PRO-[0-9A-F]{8}",
    "Sunmi P2": r"SUNMI-P2-[0-9A-F]{8}",
}
DEFAULT_CERTIFIED_FIRMWARE = {
    "PAX A920 Pro": ["2.4.1", "2.5.0"],
    "Sunmi P2": ["1.8.0"],
}


def _certified(raw: dict[str, list[str]]) -> dict[str, set[str]]:
    return {model: set(versions) for model, versions in raw.items()}


@dataclass(frozen=True)
class Settings:
    database_url: str
    ca_cert_path: Path
    ca_key_path: Path
    ca_crl_path: Path  # where the CA publishes its CRL for the mTLS gateway
    jwt_public_key: str  # PEM; verifies merchant and admin OAuth access tokens
    approved_models: dict[str, re.Pattern]
    certified_firmware: dict[str, set[str]] = field(default_factory=lambda: _certified(DEFAULT_CERTIFIED_FIRMWARE))
    card_service_url: str = "http://127.0.0.1:7070"  # card-service/ (holds the HSM and the acquirer link)
    # Step 10A: the UPI PSP. mock-psp/mock_psp.py speaks the same shapes locally.
    upi_psp_url: str = "http://127.0.0.1:8080"
    # Step 12: the wallet provider. mock-wallet/mock_wallet.py speaks the same shapes locally.
    wallet_url: str = "http://127.0.0.1:8090"
    # A UPI payment still PENDING after this long is polled for its real status (webhooks can be lost).
    upi_poll_stale_seconds: int = 300
    # Shared secret the PSP signs webhooks with. Empty means the endpoint refuses every callback (fails closed).
    upi_webhook_secret: str = ""
    # Seconds between webhook delivery runs; 0 turns the background deliverer off (tests drive it directly).
    webhook_interval: float = 2.0
    # http:// webhook URLs: local development and tests only.
    allow_insecure_webhooks: bool = False
    # Step 7 — audit log. `local` writes a WORM directory; `s3` uses S3 Object Lock (needs boto3).
    audit_worm_backend: str = "local"
    audit_worm_path: Path = Path("audit-worm")
    audit_s3_bucket: str = ""
    audit_s3_prefix: str = "audit"
    audit_retention_days: int = 1825  # five years, per RBI
    audit_alert_url: str = ""  # PagerDuty Events API v2 endpoint; empty disables alerting

    @classmethod
    def from_env(cls) -> "Settings":
        models = json.loads(os.environ.get("APPROVED_MODELS", "null")) or DEFAULT_APPROVED_MODELS
        return cls(
            database_url=os.environ["DATABASE_URL"],
            ca_cert_path=Path(os.environ["CA_CERT_PATH"]),
            ca_key_path=Path(os.environ["CA_KEY_PATH"]),
            ca_crl_path=Path(os.environ["CA_CRL_PATH"]),
            jwt_public_key=Path(os.environ["JWT_PUBLIC_KEY_PATH"]).read_text(),
            approved_models={name: re.compile(pattern) for name, pattern in models.items()},
            certified_firmware=_certified(
                json.loads(os.environ.get("CERTIFIED_FIRMWARE", "null")) or DEFAULT_CERTIFIED_FIRMWARE),
            card_service_url=os.environ.get("CARD_SERVICE_URL", "http://127.0.0.1:7070"),
            upi_psp_url=os.environ.get("UPI_PSP_URL", "http://127.0.0.1:8080"),
            wallet_url=os.environ.get("WALLET_URL", "http://127.0.0.1:8090"),
            upi_poll_stale_seconds=int(os.environ.get("UPI_POLL_STALE_SECONDS", "300")),
            upi_webhook_secret=os.environ.get("UPI_WEBHOOK_SECRET", ""),
            webhook_interval=float(os.environ.get("WEBHOOK_INTERVAL_SECONDS", "2")),
            allow_insecure_webhooks=os.environ.get("ALLOW_INSECURE_WEBHOOKS") == "1",
            audit_worm_backend=os.environ.get("AUDIT_WORM_BACKEND", "local"),
            audit_worm_path=Path(os.environ.get("AUDIT_WORM_PATH", "audit-worm")),
            audit_s3_bucket=os.environ.get("AUDIT_S3_BUCKET", ""),
            audit_s3_prefix=os.environ.get("AUDIT_S3_PREFIX", "audit"),
            audit_retention_days=int(os.environ.get("AUDIT_RETENTION_DAYS", "1825")),
            audit_alert_url=os.environ.get("AUDIT_ALERT_WEBHOOK_URL", ""),
        )
