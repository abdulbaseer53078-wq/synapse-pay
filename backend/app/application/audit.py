"""Audit query and integrity verification (Steps 7.6 and 7.7).

The query side is intentionally a thin service: support asks "what happened to this payment", and the answer
is one indexed range scan over the chained projection. The verifier is where the real logic lives — it
re-reads the WORM objects and recomputes the chain from genesis.
"""
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from app.audit.chain import GENESIS, compute_hash
from app.audit.event import from_dict
from app.infrastructure.audit_alerts import Alerter, NullAlerter
from app.infrastructure.audit_worm import epoch_of_key


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    checked: int
    chain_head: int
    first_bad_sequence: int | None
    detail: str | None


class AuditStore(Protocol):
    def search(self, correlation_id: str | None = None, entity_id: str | None = None,
               event_type: str | None = None, start: datetime | None = None, end: datetime | None = None,
               after_sequence: int | None = None, limit: int = 100) -> tuple[list[dict], int | None]: ...
    def chain_head(self) -> tuple[int, str]: ...
    def stored_hashes(self): ...
    def record_verification(self, started_at: datetime, events_checked: int, chain_head: int, status: str,
                            detail: str | None = None): ...


class AuditQueryService:
    def __init__(self, store: AuditStore):
        self.store = store

    def search(self, **filters) -> tuple[list[dict], int | None]:
        return self.store.search(**filters)

    def timeline(self, correlation_id: str, limit: int = 100) -> list[dict]:
        """Everything that happened for one correlation id, oldest first. This is the support workflow."""
        data, _ = self.store.search(correlation_id=correlation_id, limit=limit)
        return data

    def head(self) -> dict:
        sequence, digest = self.store.chain_head()
        return {"sequence": sequence, "hash": digest}


class AuditVerifier:
    """Recomputes the chain from the immutable copies and checks the database agrees.

    Two independent passes, because they catch different attacks:
      1. the WORM objects must form an unbroken chain from genesis (catches an edited or missing object);
      2. the database's sequence/hash pairs must match those objects (catches an edited database row).
    """

    def __init__(self, worm, store: AuditStore, alerter: Alerter | None = None):
        self.worm = worm
        self.store = store
        self.alerter = alerter or NullAlerter()

    def run(self) -> VerificationResult:
        started = datetime.now(UTC)
        try:
            result = self._verify()
        except Exception as exc:  # an unreadable store is a failure, but must not crash the job
            detail = f"verification error: {type(exc).__name__}: {exc}"
            self.store.record_verification(started, 0, 0, "ERROR", detail)
            self.alerter.tamper_detected(detail, 0, None)
            return VerificationResult(False, 0, 0, None, detail)

        self.store.record_verification(started, result.checked, result.chain_head,
                                       "OK" if result.ok else "TAMPERED", result.detail)
        if not result.ok:
            self.alerter.tamper_detected(result.detail or "chain mismatch", result.checked,
                                         result.first_bad_sequence)
        return result

    def _verify(self) -> VerificationResult:
        """Walks every epoch in order. Within an epoch the chain must be unbroken. A new epoch (Step 17.3) must
        start by linking to a record on the line verified so far, at or before its end: records the previous
        epoch holds after that point are the lost window of a failover, kept and reported, not an error.
        The database must then match the surviving line exactly."""
        prefix = getattr(self.worm, "prefix", "audit")
        # sequence -> (prev_hash, hash) for the surviving line.
        # shortcut: holds every sequence in memory; stream with a bounded tail once the chain reaches ~10^7 events.
        line: dict[int, tuple[str, str]] = {}
        expected, prev, checked, epoch, orphaned = 1, GENESIS, 0, None, []
        for key, data in self.worm.records():
            sequence = int(data["sequence"])
            key_epoch = epoch_of_key(key, prefix)
            if epoch is not None and key_epoch < epoch:
                return self._broken(checked, sequence, f"epoch went backwards at {key}")
            if epoch is not None and key_epoch != epoch:
                # A new epoch forks from the line at sequence - 1, which must exist (or be genesis).
                if not 1 <= sequence <= expected:
                    return self._broken(checked, sequence, f"epoch {key_epoch} starts at {sequence}, beyond the "
                                                           f"previous epoch's end ({expected - 1})")
                fork = line[sequence - 1][1] if sequence > 1 else GENESIS
                if expected - sequence:
                    orphaned.append(f"epoch {epoch} holds {expected - sequence} record(s) after sequence "
                                    f"{sequence - 1} that epoch {key_epoch} replaced (a failover's lost window)")
                for s in range(sequence, expected):
                    del line[s]
                expected, prev = sequence, fork
            epoch = key_epoch
            if sequence != expected:
                return self._broken(checked, sequence,
                                    f"sequence gap at {key}: expected {expected}, found {sequence}")
            event = from_dict(data)
            if data.get("prev_hash") != prev:
                return self._broken(checked, sequence,
                                    f"broken link at sequence {sequence}: prev_hash does not match sequence "
                                    f"{sequence - 1}")
            if compute_hash(prev, event) != data.get("hash"):
                return self._broken(checked, sequence,
                                    f"hash mismatch at sequence {sequence}: the stored content was altered")
            line[sequence] = (data["prev_hash"], data["hash"])
            prev = data["hash"]
            expected += 1
            checked += 1

        head = expected - 1
        db_head, db_hash = self.store.chain_head()
        if db_head != head or db_hash != prev:
            return self._broken(checked, None,
                                f"database head ({db_head}, {db_hash[:12]}…) does not match the WORM chain "
                                f"({head}, {prev[:12]}…)")

        # Second pass: the queryable projection must be exactly the surviving line we just verified.
        rows = 0
        for sequence, db_prev, db_digest in self.store.stored_hashes():
            rows += 1
            if line.get(sequence) != (db_prev, db_digest):
                return self._broken(checked, sequence, f"database row {sequence} disagrees with the WORM chain")
        if rows != len(line):
            return self._broken(checked, None, f"database has {rows} chained rows, the WORM line has {len(line)}")
        return VerificationResult(True, checked, head, None, "; ".join(orphaned) or None)

    @staticmethod
    def _broken(checked: int, sequence: int | None, detail: str) -> VerificationResult:
        return VerificationResult(False, checked, 0, sequence, detail)
