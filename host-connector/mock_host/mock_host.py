#!/usr/bin/env python3
"""Mock ISO 8583 acquirer host for Host Connector integration tests (Task 4.8). Standard library only.

Deliberately independent of the Rust iso8583 crate: it reads the same dialect JSON but parses and builds
messages with its own code, so a bug shared by the crate's parser and builder can't hide in a round trip.

The outcome is chosen by the request amount (DE 4, minor units), as acquirer sandboxes do:
    5100  decline: DE 39 "51" (insufficient funds)
    2000  timeout: sleep --sleep seconds (default 20), then answer "00" if the connection is still open
    9900  system error: drop the connection without answering
    else  approve: DE 39 "00" with an authorization code (DE 38)
`--soft-decline-amount N` (repeatable) adds amounts that answer DE 39 "91" (issuer unavailable): a soft decline,
the case the cascade may retry on another acquirer. It is per process, so two mock hosts can disagree about the
same amount, which is how the cross-acquirer failover test is built.
An 0800 network echo is answered with an 0810, DE 39 "00".
A reversal (0400/0420) never sleeps or drops: it is answered "00" if DE 90 quotes the MTI and STAN of a request
this mock received, else "25" (unable to locate original), whatever its amount.

    python mock_host.py --cert host.pem --key host-key.pem --client-ca ca.pem --dialect dialect.json [--port 0]

Requires a client certificate issued by --client-ca (mutual TLS, TLS 1.2+). Prints "LISTENING <port>" when
ready, then one line per message with MTI, STAN, amount and outcome only: never card data.

shortcut: ASCII MTI, binary bitmaps, ASCII fields and prefixes, 2-byte binary length header; add BCD and the
other framings when a test needs them.
"""
import argparse
import json
import socket
import ssl
import struct
import sys
import threading
import time

SCENARIOS = {5100: "decline", 2000: "timeout", 9900: "drop"}
ECHOED = (3, 4, 7, 11, 37, 41, 49)  # request fields copied into the response


class Dialect:
    def __init__(self, path):
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        raw.pop("required", None)
        if raw.pop("mti", "ascii") != "ascii" or raw.pop("bitmap", "binary") != "binary":
            sys.exit("mock_host: only ASCII MTIs and binary bitmaps are supported")
        self.fields = {int(k): v for k, v in raw.items()}
        if any("bcd" in (v.get("encoding"), v.get("prefix")) for v in self.fields.values()):
            sys.exit("mock_host: BCD fields aren't supported")

    def parse(self, msg):
        """(mti, {field: bytes}). Raises ValueError on anything malformed."""
        mti = msg[:4].decode("ascii")
        if len(mti) != 4 or not mti.isdigit():
            raise ValueError("bad MTI")
        pos, base, present = 4, 0, []
        while True:
            if len(msg) < pos + 8:
                raise ValueError("truncated bitmap")
            word = int.from_bytes(msg[pos:pos + 8], "big")
            pos += 8
            present += [base + bit for bit in range(2, 65) if word >> (64 - bit) & 1]
            if not word >> 63:
                break
            base += 64
            if base > 128:
                raise ValueError("a fourth bitmap")
        fields = {}
        for n in present:
            spec = self.fields.get(n)
            if spec is None:
                raise ValueError(f"field {n} is not in the dialect")
            if spec["type"] == "FIXED":
                length = spec["length"]
            else:
                digits = 2 if spec["type"] == "LLVAR" else 3
                prefix = msg[pos:pos + digits]
                if len(prefix) != digits or not prefix.isdigit() or int(prefix) > spec["max_length"]:
                    raise ValueError(f"field {n}: bad length prefix")
                length, pos = int(prefix), pos + digits
            value = msg[pos:pos + length]
            if len(value) != length:
                raise ValueError(f"field {n}: truncated")
            if spec["format"] == "n" and not value.isdigit():
                raise ValueError(f"field {n}: not numeric")
            fields[n], pos = value, pos + length
        if pos != len(msg):
            raise ValueError(f"{len(msg) - pos} trailing bytes")
        return mti, fields

    def build(self, mti, fields):
        words = [0, 0, 0]
        for n in fields:
            words[(n - 1) // 64] |= 1 << (63 - (n - 1) % 64)
        count = max((n - 1) // 64 for n in fields) + 1
        for i in range(count - 1):
            words[i] |= 1 << 63  # another bitmap follows
        out = mti.encode() + b"".join(w.to_bytes(8, "big") for w in words[:count])
        for n in sorted(fields):
            spec, value = self.fields[n], fields[n]
            if spec["type"] == "LLVAR":
                out += b"%02d" % len(value)
            elif spec["type"] == "LLLVAR":
                out += b"%03d" % len(value)
            out += value
        return out


def read_frame(conn):
    """One message after its 2-byte big-endian length header, or None when the peer closes."""
    def exact(n):
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    header = exact(2)
    return header and exact(struct.unpack(">H", header)[0])


def log(line):
    print(line, flush=True)


SEEN = set()  # (MTI, STAN) of every financial request received, for checking reversals' DE 90
SEEN_LOCK = threading.Lock()


def answer(dialect, conn, send_lock, mti, req, sleep, soft_decline_amounts=()):
    amount = int(req.get(4, b"0") or 0)
    if mti == "0800":
        scenario, resp_mti = "echo", "0810"
        resp = {n: req[n] for n in (7, 11, 70) if n in req}
        resp[39] = b"00"
    elif mti in ("0400", "0420"):
        original = req.get(90, b"").decode()
        with SEEN_LOCK:
            found = (original[:4], original[4:10]) in SEEN
        scenario, resp_mti = ("reversed" if found else "unknown-original"), "%04d" % (int(mti) + 10)
        resp = {n: req[n] for n in ECHOED if n in req}
        resp[39] = b"00" if found else b"25"
    else:
        with SEEN_LOCK:
            SEEN.add((mti, req.get(11, b"").decode()))
        if amount in soft_decline_amounts:
            scenario = "soft-decline"
        else:
            scenario = SCENARIOS.get(amount, "approve")
        resp_mti = "%04d" % (int(mti) + 10)
        resp = {n: req[n] for n in ECHOED if n in req}
        resp[39] = {"decline": b"51", "soft-decline": b"91"}.get(scenario, b"00")
        if scenario not in ("decline", "soft-decline"):
            resp[38] = b"AUTH%02d" % (amount % 100)
    log(f"{mti} stan={req.get(11, b'').decode()} amount={amount} -> {scenario}")
    if scenario == "drop":
        conn.shutdown(socket.SHUT_RDWR)  # no close_notify: like a host crashing or a line being cut
        return
    if scenario == "timeout":
        time.sleep(sleep)
    body = dialect.build(resp_mti, resp)
    try:
        with send_lock:
            conn.sendall(struct.pack(">H", len(body)) + body)
    except OSError:
        log(f"{resp_mti} stan={req.get(11, b'').decode()} not delivered: connection gone")


def serve(dialect, conn, sleep, soft_decline_amounts=()):
    send_lock = threading.Lock()
    try:
        while (msg := read_frame(conn)) is not None:
            try:
                mti, req = dialect.parse(msg)
            except (ValueError, UnicodeDecodeError) as e:
                log(f"rejected a malformed message ({e}); closing")
                return
            # One thread per request: a slow answer mustn't hold up the others on this connection.
            threading.Thread(target=answer, args=(dialect, conn, send_lock, mti, req, sleep, soft_decline_amounts),
                             daemon=True).start()
    except OSError:
        pass
    finally:
        conn.close()


def main():
    p = argparse.ArgumentParser(description="Mock ISO 8583 acquirer host (mutual TLS)")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--cert", required=True, help="host certificate (PEM)")
    p.add_argument("--key", required=True, help="host private key (PEM)")
    p.add_argument("--client-ca", required=True, help="CA that issues client certificates (PEM)")
    p.add_argument("--dialect", required=True, help="dialect dictionary JSON")
    p.add_argument("--sleep", type=float, default=20, help="seconds the timeout scenario waits")
    p.add_argument("--soft-decline-amount", type=int, action="append", default=[],
                   help="amount that answers DE 39 91 (soft decline); repeatable")
    args = p.parse_args()

    dialect = Dialect(args.dialect)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.cert, args.key)
    tls.verify_mode = ssl.CERT_REQUIRED
    tls.load_verify_locations(args.client_ca)

    listener = socket.create_server(("127.0.0.1", args.port))
    log(f"LISTENING {listener.getsockname()[1]}")
    while True:
        raw, _ = listener.accept()
        try:
            conn = tls.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as e:
            log(f"TLS handshake refused: {e.__class__.__name__}")
            raw.close()
            continue
        threading.Thread(target=serve, args=(dialect, conn, args.sleep, set(args.soft_decline_amount)), daemon=True).start()


if __name__ == "__main__":
    main()
