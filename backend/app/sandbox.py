"""The whole Synapse Pay sandbox on your machine, in one command (from backend/):


    python -m app.sandbox            # add --reset to start over with an empty sandbox database

Starts the mock acquirer (mutual TLS), the card service (simulated HSM, built with cargo), and the API on
http://127.0.0.1:8000, then prints a sandbox merchant's secret key and webhook secret. Needs PostgreSQL
(DATABASE_URL, default postgresql://postgres:postgres@localhost:5432/postgres), Python, Rust, and npm for the
web SDK. TEST KEYS ONLY: nothing here may touch a real card.
"""
import json
import os
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / ".sandbox"
PEM = serialization.Encoding.PEM
# The public test BDK (also in backend/tests/card_sim.py). Never use it for anything real.
TEST_BDK_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
API_PORT = int(os.environ.get("SANDBOX_PORT", "8000"))


def _key_pem(key) -> bytes:
    return key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _ca(name: str):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return cert, key


def _leaf(ca_cert, ca_key, name: str, usage, san):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
               .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=365))
               .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
    if san is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([san]), critical=False)
    return builder.sign(ca_key, hashes.SHA256()), key


def acquirer_pki(d: Path) -> None:
    """ca.pem; host.pem/host-key.pem (mock acquirer); client.pem/client-key.pem (card service)."""
    ca, ca_key = _ca("Mock Acquirer Sandbox CA")
    (d / "ca.pem").write_bytes(ca.public_bytes(PEM))
    for file, cn, usage, san in (("host", "localhost", ExtendedKeyUsageOID.SERVER_AUTH, x509.DNSName("localhost")),
                                 ("client", "synapsepay-card-service", ExtendedKeyUsageOID.CLIENT_AUTH, None)):
        cert, key = _leaf(ca, ca_key, cn, usage, san)
        (d / f"{file}.pem").write_bytes(cert.public_bytes(PEM))
        (d / f"{file}-key.pem").write_bytes(_key_pem(key))


def _keys(d: Path) -> None:
    """Everything generated once and kept, so restarts keep working: PKI, checkout key, CA, JWT key."""
    if (d / "ca.pem").exists():
        return
    d.mkdir(parents=True, exist_ok=True)
    acquirer_pki(d)
    (d / "checkout-key.pem").write_bytes(_key_pem(ec.generate_private_key(ec.SECP256R1())))
    platform_ca, platform_key = _ca("Synapse Pay Sandbox Terminal CA")
    (d / "platform-ca.pem").write_bytes(platform_ca.public_bytes(PEM))
    (d / "platform-ca-key.pem").write_bytes(_key_pem(platform_key))
    jwt = ec.generate_private_key(ec.SECP256R1())
    (d / "jwt-key.pem").write_bytes(_key_pem(jwt))
    (d / "jwt-public.pem").write_bytes(jwt.public_key().public_bytes(PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def _database(admin_url: str, reset: bool) -> str:
    name = "synapse_sandbox"
    with psycopg.connect(admin_url, autocommit=True) as admin:
        exists = admin.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,)).fetchone()
        if reset and exists:
            admin.execute(f"DROP DATABASE {name} WITH (FORCE)")
            exists = None
        if not exists:
            admin.execute(f"CREATE DATABASE {name}")
    url = admin_url.rsplit("/", 1)[0] + "/" + name
    with psycopg.connect(url, autocommit=True) as conn:
        if conn.execute("SELECT to_regclass('public.merchants')").fetchone()[0] is None:
            for migration in sorted((ROOT / "db" / "migrations").glob("*.sql")):
                conn.execute(migration.read_text())
        elif conn.execute("SELECT to_regclass('public.payment_intents')").fetchone()[0] is None:
            sys.exit("The sandbox database is from an older version: run with --reset.")
    return url


def _drain(stream) -> None:
    """Keeps reading a child's output so it never blocks on a full pipe."""
    for _ in stream:
        pass


def _start(args, env=None, cwd=None, wait_for="LISTENING ", what="process"):
    proc = subprocess.Popen(args, env=env, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in proc.stdout:
        if line.startswith(wait_for):
            threading.Thread(target=_drain, args=(proc.stdout,), daemon=True).start()
            return proc, line.split()[1]
    sys.exit(f"{what} didn't start (exit code {proc.wait()})")


def main(argv: list[str]) -> int:
    reset = "--reset" in argv
    _keys(WORK)
    admin = os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/postgres")
    database_url = _database(admin, reset)
    children = []
    try:
        dialect = ROOT / "iso8583" / "dialects" / "synthetic-host.json"
        mock, host_port = _start([sys.executable, str(ROOT / "host-connector" / "mock_host" / "mock_host.py"),
                                  "--dialect", str(dialect), "--cert", str(WORK / "host.pem"),
                                  "--key", str(WORK / "host-key.pem"), "--client-ca", str(WORK / "ca.pem"),
                                  "--sleep", "5"], what="mock acquirer")
        children.append(mock)
        print("Building the card service (first run takes a few minutes)...", flush=True)
        subprocess.run(["cargo", "build", "--quiet", "--bin", "card_service"], cwd=ROOT / "card-service", check=True)
        binary = ROOT / "card-service" / "target" / "debug" / ("card_service.exe" if os.name == "nt" else "card_service")
        env = {**os.environ, "SIM_HSM_BDK_HEX": TEST_BDK_HEX, "SIM_HSM_CHECKOUT_KEY": str(WORK / "checkout-key.pem"),
               "HOST_ADDR": f"127.0.0.1:{host_port}", "HOST_SERVER_NAME": "localhost", "HOST_CA": str(WORK / "ca.pem"),
               "HOST_CLIENT_CERT": str(WORK / "client.pem"), "HOST_CLIENT_KEY": str(WORK / "client-key.pem"),
               "HOST_DIALECT": str(dialect), "AUDIT_LOG_PATH": str(WORK / "iso-audit.jsonl"),
               "CARD_SERVICE_ADDR": "127.0.0.1:0"}
        card, card_addr = _start([str(binary)], env=env, what="card service")
        children.append(card)

        web_sdk = ROOT / "sdks" / "web"
        if not (web_sdk / "dist" / "synapsepay.js").exists():
            print("Building the web SDK...", flush=True)
            npm = "npm.cmd" if os.name == "nt" else "npm"
            subprocess.run([npm, "install", "--silent"], cwd=web_sdk, check=True)
            subprocess.run([npm, "run", "build", "--silent"], cwd=web_sdk, check=True)

        from psycopg_pool import ConnectionPool

        from app.infrastructure.postgres_api_keys import create_merchant
        saved = WORK / "merchant.json"
        merchant = json.loads(saved.read_text()) if saved.exists() and not reset else None
        if merchant:
            with psycopg.connect(database_url) as conn:
                if not conn.execute("SELECT 1 FROM merchants WHERE merchant_id = %s",
                                    (merchant["merchant_id"],)).fetchone():
                    merchant = None
        if merchant is None:
            with ConnectionPool(database_url, min_size=1, max_size=1) as pool:
                merchant = create_merchant(pool)
            saved.write_text(json.dumps(merchant, indent=2))

        import re

        import uvicorn

        from app.config import DEFAULT_APPROVED_MODELS, Settings
        from app.main import create_app
        settings = Settings(database_url, WORK / "platform-ca.pem", WORK / "platform-ca-key.pem", WORK / "platform-crl.pem",
                            (WORK / "jwt-public.pem").read_text(),
                            {name: re.compile(p) for name, p in DEFAULT_APPROVED_MODELS.items()},
                            card_service_url=f"http://{card_addr}", webhook_interval=2, allow_insecure_webhooks=True)
        print(f"""
Synapse Pay sandbox is running. TEST MODE: use test cards only.

  API             http://127.0.0.1:{API_PORT}
  Secret key      {merchant['secret_key']}
  Webhook secret  {merchant['webhook_secret']}
  (saved in {saved})

Test cards (any future expiry, any CVV): 4242 4242 4242 4242 pays without an OTP; 4111 1111 1111 1111 asks
for the OTP 123456; 4000 0000 0000 3238 fails authentication. Amount ₹51.00 is declined by the bank.

Ctrl+C stops everything.
""", flush=True)
        uvicorn.run(create_app(settings), host="127.0.0.1", port=API_PORT, log_level="warning")
    except KeyboardInterrupt:
        pass
    finally:
        for child in children:
            child.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
