"""The universal audit event (Step 7.1).

Every component emits this same envelope: the SDK, the registry, the transaction engine, the host connector.
`correlation_id` is the point — one search returns the whole story of one payment across every component.
The JSON Schema in spec/audit-event.schema.json is the authority; this module is its Python face.
"""
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

SCHEMA_VERSION = "1.0"

# Event types the platform emits today. The schema allows more (a pattern, not a closed enum) so a new
# component can start emitting without a spec release; consumers are told to key on the category prefix.
TERMINAL_EVENTS = {
    "create": "TERMINAL_CREATED",
    "register": "TERMINAL_REGISTERED",
    "activate": "TERMINAL_ACTIVATED",
    "reject": "TERMINAL_REJECTED",
    "suspend": "TERMINAL_SUSPENDED",
    "reinstate": "TERMINAL_REINSTATED",
    "revoke": "TERMINAL_REVOKED",
    "decommission": "TERMINAL_DECOMMISSIONED",
    "firmware_change": "TERMINAL_FIRMWARE_CHANGED",  # states hold firmware versions
    "health_change": "TERMINAL_HEALTH_CHANGED",  # states hold health states
}

# A transaction's final status is the event, so "why did it fail" and "what happened" read the same.
TRANSACTION_FINISH_EVENTS = {
    "AUTHORIZED": "TRANSACTION_AUTHORIZED",
    "CAPTURED": "TRANSACTION_CAPTURED",
    "SETTLED": "TRANSACTION_SETTLED",
    "FAILED": "TRANSACTION_FAILED",
    "VOIDED": "TRANSACTION_VOIDED",
    "REFUNDED": "TRANSACTION_REFUNDED",
    "PARTIALLY_REFUNDED": "TRANSACTION_REFUNDED",
    "PENDING": "TRANSACTION_PENDING",
}

TRANSACTION_EVENTS = {
    "transaction.create": "TRANSACTION_INITIATED",
    "transaction.send": "TRANSACTION_SUBMITTED",
}

# Admin reads of the registry are audited too; they are events even though nothing changed.
ADMIN_ACCESS = "ADMIN_ACCESS"


class ActorKind(StrEnum):
    MERCHANT = "merchant"
    TERMINAL = "terminal"
    ADMIN = "admin"
    SYSTEM = "system"
    SDK = "sdk"
    HOST_CONNECTOR = "host-connector"


def event_type_for(entity_type: str, action: str, to_status: str | None) -> str:
    """The universal event type for one audit_log row. Unknown combinations degrade to a readable name
    instead of raising: an audit log must never drop a fact because its label is new."""
    if entity_type == "terminal":
        return TERMINAL_EVENTS.get(action, f"TERMINAL_{action.upper()}")
    if entity_type == "transaction":
        if action == "transaction.finish":
            return TRANSACTION_FINISH_EVENTS.get(to_status or "", "TRANSACTION_STATUS_CHANGED")
        return TRANSACTION_EVENTS.get(action, f"TRANSACTION_{action.upper()}")
    if to_status is None:
        return ADMIN_ACCESS
    return f"{entity_type.upper()}_{action.upper()}"


def actor_for(actor_type: str, actor_id: str | None) -> str:
    """`merchant:{id}`, `terminal:{id}`, `admin:{id}` or plain `system` — the schema's actor format."""
    kind = actor_type.lower()
    if kind == "system" or actor_id is None:
        return "system"
    return f"{kind}:{actor_id}"


@dataclass(frozen=True)
class AuditEvent:
    event_id: UUID
    timestamp: datetime
    event_type: str
    actor: str
    entity_id: str
    correlation_id: str
    payload: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        if not self.event_type or self.event_type != self.event_type.upper():
            raise ValueError(f"event_type must be UPPER_SNAKE_CASE, got {self.event_type!r}")
        if ":" not in self.actor and self.actor != "system":
            raise ValueError(f"actor must be '<kind>:<id>' or 'system', got {self.actor!r}")

    def to_dict(self) -> dict:
        """The hashed and published form. Timestamps are millisecond ISO-8601 so they survive JSON."""
        return {
            "event_id": str(self.event_id),
            "timestamp": self.timestamp.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "event_type": self.event_type,
            "actor": self.actor,
            "entity_id": self.entity_id,
            "correlation_id": self.correlation_id,
            "payload": self.payload,
            "schema_version": SCHEMA_VERSION,
        }

    def to_json(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()


def from_audit_row(row) -> AuditEvent:
    """Build the universal event from an audit_log row.

    row: (event_id, occurred_at, actor_type, actor_id, entity_type, entity_id, action, from_status, to_status,
          reason, correlation_id, payload)
    """
    (event_id, occurred_at, actor_type, actor_id, entity_type, entity_id, action,
     from_status, to_status, reason, correlation_id, payload) = row
    return AuditEvent(
        event_id=event_id,
        timestamp=occurred_at,
        event_type=event_type_for(entity_type, action, to_status),
        actor=actor_for(actor_type, actor_id),
        entity_id=str(entity_id),
        correlation_id=correlation_id or str(entity_id),
        payload={
            **_state(from_status, to_status),
            **(payload or {}),
            **({"reason": reason} if reason else {}),
        },
    )


def from_dict(data: dict) -> AuditEvent:
    """Rebuild an event from its stored form (a WORM object or a Kafka record)."""
    return AuditEvent(
        event_id=UUID(data["event_id"]),
        timestamp=datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00")),
        event_type=data["event_type"],
        actor=data["actor"],
        entity_id=data["entity_id"],
        correlation_id=data["correlation_id"],
        payload=data.get("payload") or {},
    )


def _state(from_status: str | None, to_status: str | None) -> dict:
    state = {}
    if from_status is not None:
        state["previous_state"] = from_status
    if to_status is not None:
        state["new_state"] = to_status
    return state
