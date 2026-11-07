"""A terminal simulated with the openssl CLI, plus the request bodies it sends."""
import base64
import subprocess
from pathlib import Path

from app.domain.terminal import device_fingerprint

SE_ID, FIRMWARE, HARDWARE_ID = "SE-0001", "2.4.1", "PAX-A920PRO-0A1B2C3D"
ADMIN = "admin-ops-1"


def openssl(*args, input: bytes | None = None) -> bytes:
    return subprocess.run(["openssl", *map(str, args)], input=input, capture_output=True, check=True).stdout


class SimulatedTerminal:
    def __init__(self, workdir: Path):
        workdir.mkdir(parents=True, exist_ok=True)
        self.dir = workdir
        self.key = workdir / "terminal-key.pem"
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", self.key)

    def csr(self) -> str:
        return openssl("req", "-new", "-key", self.key, "-subj", "/CN=terminal").decode()

    def sign(self, data: bytes) -> str:
        message = self.dir / "challenge.bin"
        message.write_bytes(data)
        return base64.b64encode(openssl("dgst", "-sha256", "-sign", self.key, message)).decode()


def url(created, step):
    return f"/api/v1/terminals/{created['terminal_id']}/{step}"


def change(client, created, action, headers, reason=None):
    """POST a lifecycle action (suspend, revoke, ...)."""
    return client.post(url(created, action), headers=headers, json={"reason": reason} if reason else None)


def status_of(db, created):
    return db.execute("SELECT status FROM terminals WHERE terminal_id = %s", (created["terminal_id"],)).fetchone()[0]


def register_body(token, csr, hardware_id=HARDWARE_ID, fingerprint=None):
    return {"registration_token": token, "csr_pem": csr, "secure_element_id": SE_ID,
            "firmware_version": FIRMWARE, "hardware_id": hardware_id,
            "device_fingerprint": fingerprint or device_fingerprint(SE_ID, FIRMWARE, hardware_id)}
