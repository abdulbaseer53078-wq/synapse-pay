"""Registry events: every registry change, published from the audit log (the outbox) to the event bus.

Delivery is at-least-once and ordered per terminal; consumers drop duplicates by event_id.
"""
import json
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

TOPIC = "terminal.registry.events"

# audit_log action → event_type. Actions not listed (e.g. admin reads) are not registry events.
EVENT_TYPES = {
    "create": "TERMINAL_CREATED",
    "register": "TERMINAL_REGISTERED",
    "activate": "TERMINAL_ACTIVATED",
    "reject": "TERMINAL_REJECTED",
    "suspend": "TERMINAL_SUSPENDED",
    "reinstate": "TERMINAL_REINSTATED",
    "revoke": "TERMINAL_REVOKED",
    "decommission": "TERMINAL_DECOMMISSIONED",
    "firmware_change": "TERMINAL_FIRMWARE_CHANGED",  # states are firmware versions
    "health_change": "TERMINAL_HEALTH_CHANGED",  # states are health states
}


class EventPublishFailed(RuntimeError): ...


@dataclass(frozen=True)
class AuditRecord:
    event_id: UUID
    action: str
    terminal_id: UUID
    merchant_id: UUID
    actor_type: str
    actor_id: str | None
    occurred_at: datetime
    from_status: str | None
    to_status: str | None
    reason: str | None


@dataclass(frozen=True)
class RegistryEvent:
    event_id: UUID
    event_type: str
    terminal_id: UUID
    merchant_id: UUID
    actor: str  # system | terminal:{id} | merchant:{id} | admin:{id}
    timestamp: datetime
    previous_state: str | None
    new_state: str | None
    reason: str | None

    def to_json(self) -> bytes:
        return json.dumps({
            "event_id": str(self.event_id), "event_type": self.event_type, "terminal_id": str(self.terminal_id),
            "merchant_id": str(self.merchant_id), "actor": self.actor, "timestamp": self.timestamp.isoformat(),
            "previous_state": self.previous_state, "new_state": self.new_state, "reason": self.reason,
            "metadata": {}}).encode()


def to_event(r: AuditRecord) -> RegistryEvent:
    actor = "system" if r.actor_type == "SYSTEM" else f"{r.actor_type.lower()}:{r.actor_id}"
    return RegistryEvent(r.event_id, EVENT_TYPES[r.action], r.terminal_id, r.merchant_id, actor, r.occurred_at,
                         r.from_status, r.to_status, r.reason)


class EventOutbox(Protocol):
    def relay(self, actions: Collection[str], publish: Callable[[list[AuditRecord]], None], limit: int) -> int:
        """Passes the next unpublished records (only committed ones, in audit order) to publish, and marks them
        published only if it returns. Returns how many were published."""


class EventPublisher(Protocol):
    def publish(self, events: list[RegistryEvent]) -> None:
        """Returns once every event is durably stored, in order per terminal; raises EventPublishFailed otherwise."""


class EventRelay:
    def __init__(self, outbox: EventOutbox, publisher: EventPublisher):
        self.outbox = outbox
        self.publisher = publisher

    def run_once(self, limit: int = 500) -> int:
        return self.outbox.relay(EVENT_TYPES, lambda records: self.publisher.publish(list(map(to_event, records))),
                                 limit)
