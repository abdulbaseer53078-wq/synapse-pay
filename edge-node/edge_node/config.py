"""Edge Node settings, from the environment."""
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class EdgeConfig:
    edge_node_id: str
    merchant_id: str
    db_path: Path
    cloud_url: str  # the gateway, e.g. https://terminals.synapsepay.example
    rules_public_key_pem: str  # pinned at registration: the only key whose rules this edge accepts
    signing_key_pem: str  # the private key of this edge's certificate; signs every payment it queues
    client_cert: Path | None = None  # mTLS to the cloud
    client_key: Path | None = None
    cloud_ca: Path | None = None
    merchant_webhook_url: str = ""  # Step 24.5: where failed offline payments are reported
    merchant_webhook_secret: str = ""

    @classmethod
    def from_env(cls) -> "EdgeConfig":
        path = lambda name: Path(os.environ[name]) if os.environ.get(name) else None  # noqa: E731
        key_path = Path(os.environ["EDGE_KEY_PATH"])
        return cls(
            edge_node_id=os.environ["EDGE_NODE_ID"],
            merchant_id=os.environ["EDGE_MERCHANT_ID"],
            db_path=Path(os.environ.get("EDGE_DB_PATH", "edge.sqlite3")),
            cloud_url=os.environ["EDGE_CLOUD_URL"].rstrip("/"),
            rules_public_key_pem=Path(os.environ["EDGE_RULES_PUBLIC_KEY_PATH"]).read_text(),
            signing_key_pem=key_path.read_text(),
            client_cert=path("EDGE_CERT_PATH"),
            client_key=key_path,
            cloud_ca=path("EDGE_CLOUD_CA_PATH"),
            merchant_webhook_url=os.environ.get("EDGE_MERCHANT_WEBHOOK_URL", ""),
            merchant_webhook_secret=os.environ.get("EDGE_MERCHANT_WEBHOOK_SECRET", ""),
        )
