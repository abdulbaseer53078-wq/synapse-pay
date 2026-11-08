"""Chargebacks (PR 8): the card network's disputes, from the acquirer's notice to the outcome.

A chargeback isn't a request we can refuse: whatever the notice says is recorded, and anything that doesn't add up
(a payment we don't know, a chargeback on top of a refund) is raised to an operator rather than rejected.
"""
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Protocol
from uuid import UUID


class ChargebackStore(Protocol):
    def open(self, event_id: str, acquirer_id: str, case_id: str, network_reference: str, amount: int,
             currency: str, reason_code: str, deadline: datetime): ...
    def resolve(self, event_id: str, acquirer_id: str, case_id: str, outcome: str): ...
    def submit_evidence(self, merchant_id: UUID, chargeback_id: UUID, evidence: dict): ...
    def get(self, merchant_id: UUID, chargeback_id: UUID): ...


class Alerts(Protocol):
    def ops_alert(self, summary: str, severity: str, details: dict) -> None: ...


class ChargebackService:
    def __init__(self, store: ChargebackStore, alerts: Alerts, verify: Callable[[bytes, Mapping[str, str]], None]):
        self.store = store
        self.alerts = alerts
        self.verify = verify  # the acquirer's HMAC over "<timestamp>.<raw body>"; raises WebhookRejected

    def opened(self, event_id: str, acquirer_id: str, case_id: str, network_reference: str, amount: int,
               currency: str, reason_code: str, deadline: datetime):
        chargeback, problems, new = self.store.open(event_id, acquirer_id, case_id, network_reference, amount,
                                                    currency, reason_code, deadline)
        self._raise(problems, chargeback)
        return chargeback, new

    def resolved(self, event_id: str, acquirer_id: str, case_id: str, outcome: str):
        chargeback, problems = self.store.resolve(event_id, acquirer_id, case_id, outcome)
        self._raise(problems, chargeback)
        return chargeback

    def _raise(self, problems: list[str], chargeback) -> None:
        for problem in problems:
            self.alerts.ops_alert(f"CHARGEBACK: {problem}", "error",
                                  {"chargeback_id": str(chargeback.chargeback_id),
                                   "acquirer_case_id": chargeback.acquirer_case_id})
