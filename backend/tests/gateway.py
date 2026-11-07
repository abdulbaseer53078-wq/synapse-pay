"""Stand-in for the API gateway's mTLS check: a TLS server that requires a client certificate
chaining to the CA and checks the leaf against the CA's published CRL, as OpenSSL-based gateways do."""
import socket
import ssl
import threading
from pathlib import Path


def mtls_handshake_accepted(ca_cert: Path, crl: Path, server_cert: Path, server_key: Path,
                            client_cert: Path, client_key: Path) -> bool:
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(server_cert, server_key)
    server_ctx.verify_mode = ssl.CERT_REQUIRED
    server_ctx.load_verify_locations(cafile=ca_cert)
    server_ctx.load_verify_locations(cafile=crl)  # read fresh each call, as a gateway refreshes its CRL
    server_ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_verify_locations(cafile=ca_cert)
    client_ctx.check_hostname = False
    client_ctx.load_cert_chain(client_cert, client_key)

    result = {}
    with socket.create_server(("127.0.0.1", 0)) as listener:
        def serve():
            conn, _ = listener.accept()
            try:
                with server_ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.sendall(b"ok")
                result["accepted"] = True
            except (ssl.SSLError, OSError):
                result["accepted"] = False

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            with socket.create_connection(listener.getsockname()) as raw, client_ctx.wrap_socket(raw) as tls:
                tls.recv(2)
        except (ssl.SSLError, OSError):
            pass
        thread.join(timeout=10)
    return result["accepted"]
