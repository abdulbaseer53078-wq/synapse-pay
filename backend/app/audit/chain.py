"""Hash chaining (Step 7.3): makes silent tampering detectable.

Each stored record commits to the one before it:

    hash(n) = SHA-256( hash(n-1) || "\\n" || canonical_json(event n) )

Change any field of any record and its hash changes, so every later record's `prev_hash` no longer matches and
the break is pinpointed at exactly one sequence number. This is the same property a blockchain gets, without
the consensus machinery: we only need order and detectability, not distributed agreement.

What this does not do: stop an attacker who can rewrite the *whole* chain from genesis. That is what the WORM
store (Step 7.4) is for — it keeps an independently retained copy the attacker cannot rewrite. The chain makes
tampering visible; WORM makes it impossible to cover up.
"""
import hashlib
import json
from dataclasses import dataclass

from app.audit.event import AuditEvent

GENESIS = "0" * 64


def canonical(payload: dict) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8. Two processes must hash identically."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_hash(prev_hash: str, event: AuditEvent) -> str:
    return hashlib.sha256(prev_hash.encode("ascii") + b"\n" + canonical(event.to_dict())).hexdigest()


def verify_link(prev_hash: str, event: AuditEvent, claimed_hash: str) -> bool:
    return compute_hash(prev_hash, event) == claimed_hash


@dataclass(frozen=True)
class StoredEvent:
    """A linked event: the chain position and hashes wrapped around the universal event."""

    sequence: int
    event: AuditEvent
    prev_hash: str
    hash: str

    def to_dict(self) -> dict:
        return {**self.event.to_dict(), "sequence": self.sequence, "prev_hash": self.prev_hash, "hash": self.hash}

    def to_json(self) -> bytes:
        return canonical(self.to_dict())


class Chain:
    """Appends events to a chain starting at `head`. Pure: no I/O, so it is cheap to test and reuse."""

    def __init__(self, sequence: int = 0, head: str = GENESIS):
        self.sequence = sequence
        self.head = head

    def append(self, event: AuditEvent) -> StoredEvent:
        self.sequence += 1
        digest = compute_hash(self.head, event)
        stored = StoredEvent(self.sequence, event, self.head, digest)
        self.head = digest
        return stored
