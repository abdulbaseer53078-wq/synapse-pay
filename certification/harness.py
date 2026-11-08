"""Certification test harness (Step 27): runs matrix.json through a terminal and the real payment stack, against the
strict scheme simulator, and writes a report that POST /api/v1/certification-runs records against the model and
firmware.

A TerminalDriver makes one payment the way the terminal would. SoftwareTerminal builds the request itself; a device
driver (ADB/Appium, once a terminal app exists) would tap the same case through the real firmware instead. The
report carries the simulator's evidence per case: fields in hex, PAN masked, chip data as tags and lengths only.
"""
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Protocol
from uuid import uuid4

MATRIX = Path(__file__).with_name("matrix.json")
CURRENCY = {"INR": "0356", "USD": "0840"}  # ISO 4217 numeric, as 5F2A carries it
RID = {"VISA": "A000000003", "MASTERCARD": "A000000004", "RUPAY": "A000000524", "AMEX": "A000000025"}


class TerminalDriver(Protocol):
    name: str
    device_model: str
    firmware_version: str

    def pay(self, case: dict) -> tuple[int, dict]:
        """(HTTP status, response body) of one payment."""


def chip_data(case: dict, now: datetime) -> dict[str, str]:
    """The EMV tags a chip card and kernel produce for an online authorisation (ARQC), as hex."""
    return {"9F26": os.urandom(8).hex().upper(), "9F27": "80", "9F10": "06010A03A00000",
            "9F37": os.urandom(4).hex().upper(), "9F36": "0001", "95": "0000000000", "9A": now.strftime("%y%m%d"),
            "9C": "00", "9F02": f"{case['amount']:012d}", "5F2A": CURRENCY[case["currency"]], "82": "1980",
            "9F1A": "0356", "9F34": "420300" if case.get("pin") else "1F0302", "9F33": "E0F0C8",
            "84": RID[case["scheme"]] + "1010"}


def tlv(tags: dict[str, str]) -> str:
    return "".join(t + f"{len(v) // 2:02X}" + v for t, v in tags.items())  # every value here is under 128 bytes


class SoftwareTerminal:
    """Builds requests as certified firmware does. `tamper` edits the chip tags first: a firmware bug, for testing
    that the harness catches one."""
    name = "software"

    def __init__(self, post: Callable[[dict], tuple[int, dict]], terminal_id: str, merchant_id: str,
                 device_model: str, firmware_version: str, encrypt_card: Callable[[str], str],
                 encrypt_pin: Callable[[str, str], str], tamper: Callable[[dict], None] | None = None):
        self.post, self.terminal_id, self.merchant_id = post, terminal_id, merchant_id
        self.device_model, self.firmware_version = device_model, firmware_version
        self.encrypt_card, self.encrypt_pin, self.tamper = encrypt_card, encrypt_pin, tamper

    def pay(self, case: dict) -> tuple[int, dict]:
        tags = chip_data(case, datetime.now(UTC))
        if self.tamper:
            self.tamper(tags)
        details = {"encrypted_card_data": self.encrypt_card(case["pan"]), "card_expiry": case["expiry"],
                   "card_network": case["scheme"], "emv_data": tlv(tags)}
        if case.get("pin"):
            details["pin_block"] = self.encrypt_pin(case["pin"], case["pan"])
        return self.post({"idempotency_key": str(uuid4()), "amount": case["amount"], "currency": case["currency"],
                          "payment_method": "CARD", "method_details": details, "terminal_id": self.terminal_id,
                          "merchant_id": self.merchant_id})


def _lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def run(driver: TerminalDriver, evidence: Path, matrix: Path = MATRIX) -> dict:
    """Runs every case in order. Cases run one at a time, so a case's evidence is what the simulator logged
    while it ran."""
    cases = []
    for case in json.loads(matrix.read_text(encoding="utf-8"))["cases"]:
        before = len(_lines(evidence))
        status, body = driver.pay(case)
        seen = _lines(evidence)[before:]
        got = {"http": status, "status": body.get("status"),
               "error_code": (body.get("error") or {}).get("error_code") or body.get("error_code"),
               "de39": seen[-1]["de39"] if seen else None}
        cases.append({"id": case["id"], "scheme": case["scheme"], "expect": case["expect"],
                      "got": {k: got[k] for k in case["expect"]},
                      "passed": all(got[k] == v for k, v in case["expect"].items()), "evidence": seen})
    return {"device_model": driver.device_model, "firmware_version": driver.firmware_version, "driver": driver.name,
            "ran_at": datetime.now(UTC).isoformat(), "passed": all(c["passed"] for c in cases), "cases": cases}
