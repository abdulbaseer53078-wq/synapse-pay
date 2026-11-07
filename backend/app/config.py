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
    # Seconds between webhook delivery runs; 0 turns the background deliverer off (tests drive it directly).
    webhook_interval: float = 2.0
    # http:// webhook URLs: local development and tests only.
    allow_insecure_webhooks: bool = False

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
            webhook_interval=float(os.environ.get("WEBHOOK_INTERVAL_SECONDS", "2")),
            allow_insecure_webhooks=os.environ.get("ALLOW_INSECURE_WEBHOOKS") == "1",
        )
