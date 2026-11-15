"""Sandbox shims. Loaded with `-p tmpmode`; not part of the repo's test config."""
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_mkdir = os.mkdir


def mkdir(path, mode=0o777, *, dir_fd=None):
    return _mkdir(path, 0o777, dir_fd=dir_fd)


os.mkdir = mkdir


def fake_openssl(*args, input=None):
    args = [str(a) for a in args]
    command = args[0]

    def option(name):
        return args[args.index(name) + 1]

    def key_from(path):
        return serialization.load_pem_private_key(open(path, "rb").read(), password=None)

    if command == "ecparam":
        key = ec.generate_private_key(ec.SECP256R1())
        with open(option("-out"), "wb") as handle:
            handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        return b""
    if command == "req":
        if "-inform" in args:
            return x509.load_der_x509_csr(input).public_bytes(serialization.Encoding.PEM)
        key = key_from(option("-key"))
        common_name = option("-subj").lstrip("/").split("=", 1)[1]
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
               .sign(key, hashes.SHA256()))
        return csr.public_bytes(serialization.Encoding.PEM)
    if command == "dgst":
        key = key_from(option("-sign"))
        return key.sign(open(args[-1], "rb").read(), ec.ECDSA(hashes.SHA256()))
    raise RuntimeError(f"openssl shim does not implement: {args}")


def pytest_configure(config):
    import shutil

    import terminal_sim

    terminal_sim.openssl = fake_openssl
    real_which = shutil.which

    def which(command, *args, **kwargs):
        return "openssl-shim" if command == "openssl" else real_which(command, *args, **kwargs)

    shutil.which = which
