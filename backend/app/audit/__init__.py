"""The audit library (Step 7). Pure and dependency-free: future services import this and nothing else.

    from app.audit import AuditEvent, sanitize, event_type_for

A service never writes to a WORM store or a chain directly — it writes the durable fact (its own outbox row
or an audit_log row) and the ingester does the rest. That keeps `audit.log(...)` non-blocking, which is what
lets the payment path stay fast.
"""
from app.audit.chain import GENESIS, Chain, StoredEvent, canonical, compute_hash, verify_link
from app.audit.event import (SCHEMA_VERSION, ActorKind, AuditEvent, actor_for, event_type_for, from_audit_row,
                             from_dict)
from app.audit.sanitize import REMOVED, luhn_ok, mask_pan, sanitize

__all__ = [
    "GENESIS", "REMOVED", "SCHEMA_VERSION", "ActorKind", "AuditEvent", "Chain", "StoredEvent", "actor_for",
    "canonical", "compute_hash", "event_type_for", "from_audit_row", "from_dict", "luhn_ok", "mask_pan",
    "sanitize", "verify_link",
]
