"""The certification registry (Step 26): the matrix every transaction is checked against, and its admin.

Every transaction asks the matrix, so it lives in memory: one dictionary lookup, no query. It is reloaded whenever
an admin changes it (the repository notifies every API process in the same database transaction as the change)
and whenever the notification channel reconnects, so a revocation applies to the very next payment.

Fail closed: until the matrix has loaded, or if a reload fails, every firmware is uncertified. Refusing a payment
for a minute costs less than a scheme fine for taking one on an uncertified device.
"""
import threading
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from app.application.registration import Conflict, InvalidInput
from app.domain.certification import (Certification, below_minimum, certified_acquirers, firmware_denial,
                                      schemes_for, version_key)


@dataclass(frozen=True)
class Snapshot:
    rows: dict[tuple[str, str], list[Certification]]
    minimums: dict[str, str]


class CertificationStore(Protocol):
    def load(self) -> Snapshot: ...
    def create(self, cert: Certification, actor_id: str) -> None: ...
    def update(self, certification_id: UUID, status: str | None, valid_until: datetime | None,
               actor_id: str) -> Certification: ...
    def set_minimum(self, device_model: str, minimum: str, actor_id: str) -> None: ...
    def list(self, device_model: str | None, firmware_version: str | None) -> list[Certification]: ...


@dataclass(frozen=True)
class CertificationRun:
    """One certification test harness run (Step 27) for an exact model and firmware."""
    run_id: UUID
    device_model: str
    firmware_version: str
    driver: str
    passed: bool
    schemes: frozenset[str]
    report: dict
    recorded_at: datetime | None = None


class CertificationRunStore(Protocol):
    def record(self, run: CertificationRun, actor_id: str) -> CertificationRun: ...
    def latest(self, device_model: str, firmware_version: str) -> CertificationRun | None: ...


def snapshot(rows: list[Certification], minimums: dict[str, str]) -> Snapshot:
    by_firmware: dict[tuple[str, str], list[Certification]] = defaultdict(list)
    for row in rows:
        by_firmware[(row.device_model, row.firmware_version)].append(row)
    return Snapshot(dict(by_firmware), dict(minimums))


class CertificationMatrix:
    def __init__(self, store: CertificationStore, now=lambda: datetime.now(UTC)):
        self.store = store
        self.now = now
        self._snapshot: Snapshot | None = None
        self._lock = threading.Lock()

    def reload(self) -> None:
        try:
            fresh = self.store.load()
        except Exception:
            with self._lock:
                self._snapshot = None  # a matrix we can't read certifies nothing
            raise
        with self._lock:
            self._snapshot = fresh

    @property
    def loaded(self) -> bool:
        return self._snapshot is not None

    def denial(self, device_model: str, firmware: str | None, method: str | None = None,
               card_network: str | None = None) -> str | None:
        """FIRMWARE_UNCERTIFIED, CERTIFICATION_EXPIRED or None. With no method: certified for any scheme."""
        snap = self._snapshot
        if snap is None or firmware is None:
            return "FIRMWARE_UNCERTIFIED"
        schemes = schemes_for(method, card_network) if method else None
        return firmware_denial(snap.rows.get((device_model, firmware), []), snap.minimums.get(device_model),
                               firmware, schemes, self.now())

    def is_certified(self, device_model: str, firmware_version: str) -> bool:
        return self.denial(device_model, firmware_version) is None

    def is_downgrade(self, device_model: str, firmware_version: str) -> bool:
        snap = self._snapshot
        return snap is not None and below_minimum(firmware_version, snap.minimums.get(device_model))

    def acquirers(self, device_model: str, firmware: str, method: str, card_network: str | None) -> frozenset[str]:
        """The acquirers this firmware is certified with for this payment's scheme: the only hosts it may route to."""
        snap = self._snapshot
        if snap is None:
            return frozenset()
        return certified_acquirers(snap.rows.get((device_model, firmware), []), schemes_for(method, card_network),
                                   self.now())


class CertificationAdmin:
    """registry:admin changes to the matrix. The store audits each one and notifies every process to reload."""

    def __init__(self, store: CertificationStore, runs: CertificationRunStore):
        self.store = store
        self.runs = runs

    def create(self, cert: Certification, actor_id: str) -> Certification:
        if version_key(cert.firmware_version) is None:
            raise InvalidInput("firmware_version must be an exact dotted version, e.g. 2.4.1 or v2.1.4")
        # Step 27: the latest run decides, so a regression found after an earlier pass blocks approval.
        run = self.runs.latest(cert.device_model, cert.firmware_version)
        if run is None or not run.passed or cert.scheme not in run.schemes:
            raise Conflict(f"the latest certification test run for this firmware didn't pass {cert.scheme}",
                           code="CERTIFICATION_RUN_REQUIRED")
        self.store.create(cert, actor_id)
        return cert

    def update(self, certification_id: UUID, status: str | None, valid_until: datetime | None,
               actor_id: str) -> Certification:
        if status is None and valid_until is None:
            raise InvalidInput("nothing to change: give status, valid_until or both")
        return self.store.update(certification_id, status, valid_until, actor_id)

    def set_minimum(self, device_model: str, minimum: str, actor_id: str) -> None:
        if version_key(minimum) is None:
            raise InvalidInput("minimum_secure_firmware must be a dotted version, e.g. 2.4.0")
        self.store.set_minimum(device_model, minimum, actor_id)

    def list(self, device_model: str | None, firmware_version: str | None) -> list[Certification]:
        return self.store.list(device_model, firmware_version)

    def record_run(self, device_model: str, firmware_version: str, driver: str, report: dict,
                   actor_id: str) -> CertificationRun:
        """`report` is the harness's: a run passes only if it has cases and every one passed."""
        if version_key(firmware_version) is None:
            raise InvalidInput("firmware_version must be an exact dotted version, e.g. 2.4.1 or v2.1.4")
        cases = report["cases"]
        passed = bool(cases) and all(c["passed"] for c in cases)
        run = CertificationRun(uuid4(), device_model, firmware_version, driver, passed,
                               frozenset(c["scheme"] for c in cases), report)
        return self.runs.record(run, actor_id)
