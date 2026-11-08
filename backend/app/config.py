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


@dataclass(frozen=True)
class Settings:
    database_url: str
    ca_cert_path: Path
    ca_key_path: Path
    ca_crl_path: Path  # where the CA publishes its CRL for the mTLS gateway
    jwt_public_key: str  # PEM; verifies merchant and admin OAuth access tokens
    approved_models: dict[str, re.Pattern]
    card_service_url: str = "http://127.0.0.1:7070"  # card-service/ (holds the HSM and the acquirer link)
    # Step 10A: the UPI PSP. mock-psp/mock_psp.py speaks the same shapes locally.
    upi_psp_url: str = "http://127.0.0.1:8080"
    # Step 12: the wallet provider. mock-wallet/mock_wallet.py speaks the same shapes locally.
    wallet_url: str = "http://127.0.0.1:8090"
    # A UPI payment still PENDING after this long is polled for its real status (webhooks can be lost).
    upi_poll_stale_seconds: int = 300
    # Shared secret the PSP signs webhooks with. Empty means the endpoint refuses every callback (fails closed).
    upi_webhook_secret: str = ""
    # Same, for the wallet provider (Step 12b). A separate secret: rotating one must not touch the other.
    wallet_webhook_secret: str = ""
    # Step 14.8: how often to poll card-service for its host health, and which card hosts it is expected to
    # report. Named, so a failed poll can say "acquirer_a DOWN" instead of "no card hosts".
    health_poll_seconds: float = 5.0
    card_hosts: tuple[str, ...] = ("acquirer_a", "acquirer_b")
    # Step 15: the host preference per payment method, e.g. {"CARD": ["acquirer_a", "acquirer_b"]}. These are
    # fleet-wide defaults until per-merchant rules have a table. Empty disables routing and its cascade.
    routing_rules: dict[str, tuple[str, ...]] = field(default_factory=dict)
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
    # Step 17.4 — who signs terminal certificates. `file`: a key on local disk (development, one process only).
    # `aws_pca`: AWS Private CA, shared by every instance in every region; the ca_*_path settings are unused.
    ca_backend: str = "file"
    aws_pca_arn: str = ""
    aws_pca_signing_algorithm: str = "SHA256WITHECDSA"  # must match the CA's key: SHA256WITHRSA for an RSA CA
    # Step 18: Prometheus metrics on their own port (never the public API port). 0 disables the server.
    metrics_port: int = 0
    # Step 20: PEM of the ECDSA P-256 key that signs edge nodes' offline rules. Empty: edge rules unavailable.
    edge_rules_signing_key: str = ""

    @classmethod
    def from_env(cls) -> "Settings":
        models = json.loads(os.environ.get("APPROVED_MODELS", "null")) or DEFAULT_APPROVED_MODELS
        ca_backend = os.environ.get("CA_BACKEND", "file")
        if ca_backend not in ("file", "aws_pca"):
            raise ValueError(f"CA_BACKEND must be file or aws_pca, not {ca_backend!r}")
        # The file CA needs its key and CRL paths; with AWS Private CA they don't exist.
        ca_path = (lambda name: Path(os.environ[name])) if ca_backend == "file" else (lambda name: Path(""))
        return cls(
            database_url=os.environ["DATABASE_URL"],
            ca_cert_path=ca_path("CA_CERT_PATH"),
            ca_key_path=ca_path("CA_KEY_PATH"),
            ca_crl_path=ca_path("CA_CRL_PATH"),
            jwt_public_key=Path(os.environ["JWT_PUBLIC_KEY_PATH"]).read_text(),
            approved_models={name: re.compile(pattern) for name, pattern in models.items()},
            card_service_url=os.environ.get("CARD_SERVICE_URL", "http://127.0.0.1:7070"),
            upi_psp_url=os.environ.get("UPI_PSP_URL", "http://127.0.0.1:8080"),
            wallet_url=os.environ.get("WALLET_URL", "http://127.0.0.1:8090"),
            upi_poll_stale_seconds=int(os.environ.get("UPI_POLL_STALE_SECONDS", "300")),
            upi_webhook_secret=os.environ.get("UPI_WEBHOOK_SECRET", ""),
            wallet_webhook_secret=os.environ.get("WALLET_WEBHOOK_SECRET", ""),
            health_poll_seconds=float(os.environ.get("HEALTH_POLL_SECONDS", "5")),
            card_hosts=tuple(h for h in os.environ.get("CARD_HOSTS", "acquirer_a,acquirer_b").split(",") if h),
            routing_rules={method: tuple(hosts) for method, hosts in
                           (json.loads(os.environ.get("ROUTING_RULES", "null")) or {}).items()},
            webhook_interval=float(os.environ.get("WEBHOOK_INTERVAL_SECONDS", "2")),
            allow_insecure_webhooks=os.environ.get("ALLOW_INSECURE_WEBHOOKS") == "1",
            audit_worm_backend=os.environ.get("AUDIT_WORM_BACKEND", "local"),
            audit_worm_path=Path(os.environ.get("AUDIT_WORM_PATH", "audit-worm")),
            audit_s3_bucket=os.environ.get("AUDIT_S3_BUCKET", ""),
            audit_s3_prefix=os.environ.get("AUDIT_S3_PREFIX", "audit"),
            audit_retention_days=int(os.environ.get("AUDIT_RETENTION_DAYS", "1825")),
            audit_alert_url=os.environ.get("AUDIT_ALERT_WEBHOOK_URL", ""),
            ca_backend=ca_backend,
            aws_pca_arn=os.environ["AWS_PCA_ARN"] if ca_backend == "aws_pca" else "",
            aws_pca_signing_algorithm=os.environ.get("AWS_PCA_SIGNING_ALGORITHM", "SHA256WITHECDSA"),
            metrics_port=int(os.environ.get("METRICS_PORT", "0")),
            edge_rules_signing_key=(Path(os.environ["EDGE_RULES_KEY_PATH"]).read_text()
                                    if os.environ.get("EDGE_RULES_KEY_PATH") else ""),
        )
