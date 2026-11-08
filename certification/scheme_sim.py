#!/usr/bin/env python3
"""Strict card scheme simulator for the certification test harness (Step 27). Standard library only.

A drop-in for host-connector/mock_host/mock_host.py, whose dialect parser, framing and answers it reuses: it speaks
the same ISO 8583 over mutual TLS, but checks each financial request the way a scheme's test host does before
answering it:

    DE 2   Luhn and a known BIN range                          else DE 39 "14" (invalid card number)
    DE 14  not expired                                         else DE 39 "54" (expired card)
    DE 22  chip entry ("05x") carries DE 55                    else DE 39 "30" (format error)
    DE 55  strict BER-TLV: no padding, no constructed or repeated tags, minimal lengths, nothing left over;
           every required tag at its length; AID (84) of the card's scheme; 9F02 = DE 4, 5F2A = DE 49, 9C = DE 3
                                                               else DE 39 "30"
A request that passes is answered as mock_host answers it (5100 declines "51", anything else approves).

Each financial request leaves one JSON line in --evidence: MTI, STAN, amount, scheme, DE 39, findings, and every
field in hex, except DE 2 (masked), DE 14 (left out) and DE 55 (tags and lengths only, never values).

    python scheme_sim.py --cert host.pem --key host-key.pem --client-ca ca.pem --dialect dialect.json \
        --evidence evidence.jsonl [--port 0]

shortcut: required tags are the EMV Book 3 online-authorisation data, the same for every scheme; load each scheme's
own test plan list once there's a signed one to copy. Every request is checked as chip (the card service sends
DE 22 "051"); add keyed and contactless entry modes when the card service sends them.
"""
import argparse
import json
import socket
import ssl
import struct
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host-connector" / "mock_host"))
import mock_host  # noqa: E402

# tag: (min, max) length in bytes
REQUIRED = {"9F26": (8, 8), "9F27": (1, 1), "9F10": (1, 32), "9F37": (4, 4), "9F36": (2, 2), "95": (5, 5),
            "9A": (3, 3), "9C": (1, 1), "9F02": (6, 6), "5F2A": (2, 2), "82": (2, 2), "9F1A": (2, 2),
            "9F34": (3, 3), "9F33": (3, 3), "84": (5, 16)}
RIDS = {"VISA": "A000000003", "MASTERCARD": "A000000004", "RUPAY": "A000000524", "AMEX": "A000000025"}


def scheme_of(pan: str) -> str | None:
    if pan[:1] == "4":
        return "VISA"
    if pan[:2] in ("34", "37"):
        return "AMEX"
    if "51" <= pan[:2] <= "55" or "2221" <= pan[:4] <= "2720":
        return "MASTERCARD"
    if pan[:2] in ("60", "65", "81", "82") or pan[:3] == "508":
        return "RUPAY"
    return None


def luhn_ok(pan: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(pan)):
        d = int(ch) * (2 if i % 2 else 1)
        total += d - 9 if d > 9 else d
    return total % 10 == 0


def parse_tlv(data: bytes) -> dict[str, bytes]:
    """Strict, flat BER-TLV. Raises ValueError naming the problem, never a value."""
    out, pos = {}, 0
    while pos < len(data):
        if data[pos] in (0x00, 0xFF):
            raise ValueError(f"padding byte at offset {pos}")
        start = pos
        if data[pos] & 0x20:
            raise ValueError(f"constructed tag at offset {pos}")
        if data[pos] & 0x1F == 0x1F:
            pos += 1
            while pos < len(data) and data[pos] & 0x80:
                pos += 1
        pos += 1
        if pos > len(data):
            raise ValueError("truncated tag")
        tag = data[start:pos].hex().upper()
        if pos >= len(data):
            raise ValueError(f"tag {tag}: no length")
        first = data[pos]
        pos += 1
        if first < 0x80:
            length = first
        elif first in (0x81, 0x82):
            n = first - 0x80
            length = int.from_bytes(data[pos:pos + n], "big")
            if len(data[pos:pos + n]) != n or length < (0x80 if n == 1 else 0x100):
                raise ValueError(f"tag {tag}: non-minimal or truncated length")
            pos += n
        else:
            raise ValueError(f"tag {tag}: unsupported length form")
        if pos + length > len(data):
            raise ValueError(f"tag {tag}: value runs past the end")
        if tag in out:
            raise ValueError(f"tag {tag} repeated")
        out[tag], pos = data[pos:pos + length], pos + length
    return out


def check(req: dict[int, bytes], today: datetime) -> tuple[str | None, str | None, list[str]]:
    """(DE 39 to refuse with, or None to answer normally; the card's scheme; findings)."""
    pan = req.get(2, b"").decode()
    scheme = scheme_of(pan)
    if not pan or not luhn_ok(pan) or scheme is None:
        return "14", scheme, ["DE 2: fails Luhn or no known BIN range"]
    expiry = req.get(14, b"").decode()
    if len(expiry) != 4 or not expiry.isdigit() or not 1 <= int(expiry[2:]) <= 12:
        return "30", scheme, ["DE 14: not YYMM"]
    if expiry < today.strftime("%y%m"):
        return "54", scheme, ["DE 14: expired"]
    if not req.get(22, b"").startswith(b"05"):
        return None, scheme, []
    if 55 not in req:
        return "30", scheme, ["DE 55: missing on a chip transaction"]
    try:
        tlv = parse_tlv(req[55])
    except ValueError as e:
        return "30", scheme, [f"DE 55: {e}"]
    findings = [f"DE 55: tag {t} missing" for t in REQUIRED if t not in tlv]
    findings += [f"DE 55: tag {t} is {len(tlv[t])} bytes, expected {lo}..{hi}"
                 for t, (lo, hi) in REQUIRED.items() if t in tlv and not lo <= len(tlv[t]) <= hi]
    if "84" in tlv and not tlv["84"].hex().upper().startswith(RIDS[scheme]):
        findings.append(f"DE 55: AID is not a {scheme} application")
    if "9F02" in tlv and tlv["9F02"].hex() != req.get(4, b"").decode():
        findings.append("DE 55: 9F02 differs from DE 4")
    if "5F2A" in tlv and tlv["5F2A"].hex() != "0" + req.get(49, b"").decode():
        findings.append("DE 55: 5F2A differs from DE 49")
    if "9C" in tlv and tlv["9C"].hex() != req.get(3, b"").decode()[:2]:
        findings.append("DE 55: 9C differs from DE 3")
    return ("30" if findings else None), scheme, findings


def evidence(mti: str, req: dict[int, bytes], scheme, de39: str, findings: list[str]) -> dict:
    fields = {}
    for n, v in sorted(req.items()):
        if n == 2:
            pan = v.decode()
            fields["2"] = pan[:6] + "*" * (len(pan) - 10) + pan[-4:]
        elif n == 55:
            try:
                fields["55"] = [[t, len(x)] for t, x in parse_tlv(v).items()]
            except ValueError:
                fields["55"] = f"unparseable, {len(v)} bytes"
        elif n != 14:
            fields[str(n)] = v.hex().upper()
    return {"mti": mti, "stan": req.get(11, b"").decode(), "amount": int(req.get(4, b"0") or 0), "scheme": scheme,
            "de39": de39, "findings": findings, "fields": fields}


def serve(dialect, conn, sleep, out, out_lock):
    send_lock = threading.Lock()
    try:
        while (msg := mock_host.read_frame(conn)) is not None:
            try:
                mti, req = dialect.parse(msg)
            except (ValueError, UnicodeDecodeError) as e:
                mock_host.log(f"rejected a malformed message ({e}); closing")
                return
            if mti not in ("0100", "0200"):
                threading.Thread(target=mock_host.answer, args=(dialect, conn, send_lock, mti, req, sleep),
                                 daemon=True).start()
                continue
            refuse, scheme, findings = check(req, datetime.now(UTC))
            de39 = refuse or ("51" if int(req.get(4, b"0") or 0) == 5100 else "00")
            with out_lock:
                out.write(json.dumps(evidence(mti, req, scheme, de39, findings)) + "\n")
                out.flush()
            if refuse is None:
                threading.Thread(target=mock_host.answer, args=(dialect, conn, send_lock, mti, req, sleep),
                                 daemon=True).start()
                continue
            mock_host.log(f"{mti} stan={req.get(11, b'').decode()} -> {refuse} ({len(findings)} findings)")
            resp = {n: req[n] for n in mock_host.ECHOED if n in req}
            resp[39] = refuse.encode()
            body = dialect.build("%04d" % (int(mti) + 10), resp)
            with send_lock:
                conn.sendall(struct.pack(">H", len(body)) + body)
    except OSError:
        pass
    finally:
        conn.close()


def main():
    p = argparse.ArgumentParser(description="Strict card scheme simulator (mutual TLS)")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--client-ca", required=True)
    p.add_argument("--dialect", required=True)
    p.add_argument("--evidence", required=True, help="JSON lines, one per financial request")
    p.add_argument("--sleep", type=float, default=20)
    args = p.parse_args()

    dialect = mock_host.Dialect(args.dialect)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.cert, args.key)
    tls.verify_mode = ssl.CERT_REQUIRED
    tls.load_verify_locations(args.client_ca)
    out, out_lock = open(args.evidence, "a", encoding="utf-8"), threading.Lock()

    listener = socket.create_server(("127.0.0.1", args.port))
    mock_host.log(f"LISTENING {listener.getsockname()[1]}")
    while True:
        raw, _ = listener.accept()
        try:
            conn = tls.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as e:
            mock_host.log(f"TLS handshake refused: {e.__class__.__name__}")
            raw.close()
            continue
        threading.Thread(target=serve, args=(dialect, conn, args.sleep, out, out_lock), daemon=True).start()


if __name__ == "__main__":
    main()
