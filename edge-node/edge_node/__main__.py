"""Run the Edge Node: the local API on :8080 and the sync worker beside it.

    python -m edge_node        (env: see config.py; EDGE_TLS_CERT/EDGE_TLS_KEY/EDGE_TLS_CLIENT_CA enable TLS with
                                terminal client certificates required, which is how it should run in a shop)
"""
import logging
import os
import ssl
import threading

import httpx
import uvicorn

from edge_node.config import EdgeConfig
from edge_node.engine import create_app
from edge_node.sync import SyncWorker


def cloud(cfg: EdgeConfig) -> httpx.Client:
    cert = (str(cfg.client_cert), str(cfg.client_key)) if cfg.client_cert else None
    return httpx.Client(base_url=cfg.cloud_url, cert=cert, verify=str(cfg.cloud_ca) if cfg.cloud_ca else True,
                        timeout=10)


def worker(cfg: EdgeConfig) -> SyncWorker:
    client = cloud(cfg)

    def fetch_rules() -> dict:
        return client.get("/internal/v1/edge/rules").raise_for_status().json()

    def send(items: list[dict]) -> tuple[int, dict | None]:
        r = client.post("/api/v1/transactions/sync", json={"transactions": items})
        return r.status_code, (r.json() if r.headers.get("content-type", "").startswith("application/json") else None)

    def post(url: str, raw: bytes, headers: dict) -> int:
        return httpx.post(url, content=raw, headers=headers, timeout=5).status_code

    return SyncWorker(cfg, fetch_rules, send, post)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    cfg = EdgeConfig.from_env()
    app = create_app(cfg)
    threading.Thread(target=worker(cfg).run_forever, daemon=True, name="edge-sync").start()
    tls = {}
    if os.environ.get("EDGE_TLS_CERT"):
        tls = {"ssl_certfile": os.environ["EDGE_TLS_CERT"], "ssl_keyfile": os.environ["EDGE_TLS_KEY"],
               "ssl_ca_certs": os.environ["EDGE_TLS_CLIENT_CA"], "ssl_cert_reqs": ssl.CERT_REQUIRED}
    uvicorn.run(app, host=os.environ.get("EDGE_HOST", "0.0.0.0"), port=int(os.environ.get("EDGE_PORT", "8080")),
                log_level="info", **tls)


if __name__ == "__main__":
    main()
