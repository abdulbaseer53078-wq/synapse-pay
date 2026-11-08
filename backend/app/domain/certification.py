"""The certification matrix (Step 26): which exact firmware may take which scheme through which acquirer.

Pure rules over rows already loaded; no I/O. Matching is exact on (model, firmware): "2.1.x" is never certified,
only the versions that have their own row.
"""
import re
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

CARD_SCHEMES = frozenset({"VISA", "MASTERCARD", "RUPAY", "AMEX"})
UPI_SCHEME = "NPCI_UPI"
_VERSION = re.compile(r"^v?(\d+(?:\.\d+)*)$")


@dataclass(frozen=True)
class Certification:
    certification_id: UUID
    device_model: str
    firmware_version: str
    scheme: str
    acquirer_id: str
    certificate_number: str
    status: str
    valid_from: datetime
    valid_until: datetime

    def in_force(self, now: datetime) -> bool:
        return self.status == "ACTIVE" and self.valid_from <= now < self.valid_until


def schemes_for(method: str, card_network: str | None = None) -> frozenset[str] | None:
    """The schemes a payment needs certifying for; None when no scheme certifies the rail (wallet, offline)."""
    if method == "CARD":
        return frozenset({card_network}) if card_network in CARD_SCHEMES else CARD_SCHEMES
    if method in ("UPI", "QR"):
        return frozenset({UPI_SCHEME})
    return None


def version_key(version: str) -> tuple[int, ...] | None:
    match = _VERSION.match(version.strip())
    return tuple(int(p) for p in match.group(1).split(".")) if match else None


def below_minimum(firmware: str, minimum: str | None) -> bool:
    """True if `firmware` is older than the model's minimum secure version, or can't be compared to it."""
    if minimum is None:
        return False
    have, need = version_key(firmware), version_key(minimum)
    if have is None or need is None:
        return True  # fail closed: an unreadable version can't prove it isn't a downgrade
    width = max(len(have), len(need))
    return have + (0,) * (width - len(have)) < need + (0,) * (width - len(need))


def firmware_denial(rows: list[Certification], minimum: str | None, firmware: str, schemes: frozenset[str] | None,
                    now: datetime) -> str | None:
    """Why this firmware may not take this payment, or None. `rows` are the model+firmware's certifications."""
    if below_minimum(firmware, minimum):
        return "FIRMWARE_UNCERTIFIED"
    relevant = [r for r in rows if schemes is None or r.scheme in schemes]
    if not relevant:
        return "FIRMWARE_UNCERTIFIED"
    if not any(r.in_force(now) for r in relevant):
        return "CERTIFICATION_EXPIRED"
    return None


def certified_acquirers(rows: list[Certification], schemes: frozenset[str] | None, now: datetime) -> frozenset[str]:
    return frozenset(r.acquirer_id for r in rows if r.in_force(now) and (schemes is None or r.scheme in schemes))
