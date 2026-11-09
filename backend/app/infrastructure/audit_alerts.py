"""Alerting (Step 7.7): a tamper finding must reach a human, not a log file.

PagerDuty's Events API v2 accepts `{routing_key, event_action, payload{summary, severity, source, custom_details}}`.
`AUDIT_ALERT_WEBHOOK_URL` points at that endpoint, or at any internal alert sink that takes the same shape.
The default is a no-op so tests and local runs are silent.
"""
import json
import urllib.error
import urllib.request
from typing import Protocol


class Alerter(Protocol):
    def tamper_detected(self, detail: str, checked: int, sequence: int | None) -> None: ...
    def ops_alert(self, summary: str, severity: str, details: dict) -> None: ...


class NullAlerter:
    def tamper_detected(self, detail: str, checked: int, sequence: int | None) -> None:
        return None

    def ops_alert(self, summary: str, severity: str, details: dict) -> None:
        print(f"ALERT ({severity}, no alert webhook configured): {summary}")


class WebhookAlerter:
    """POSTs a PagerDuty-compatible event. Never raises: a failed alert must not stop verification."""

    def __init__(self, url: str, routing_key: str = "synapsepay-audit", timeout: float = 5.0):
        self.url = url
        self.routing_key = routing_key
        self.timeout = timeout

    def ops_alert(self, summary: str, severity: str, details: dict) -> None:
        """Anything an operator must look at now: a broken edge chain, money the bank and the ledger disagree on."""
        self._send({"summary": summary, "severity": severity, "source": "synapsepay", "custom_details": details},
                   summary)

    def _send(self, payload: dict, detail: str) -> None:
        body = json.dumps({"routing_key": self.routing_key, "event_action": "trigger", "payload": payload}).encode()
        request = urllib.request.Request(self.url, data=body, method="POST",
                                         headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(request, timeout=self.timeout).close()
        except (urllib.error.URLError, OSError) as exc:  # pragma: no cover - network dependent
            print(f"ALERT DELIVERY FAILED ({type(exc).__name__}): {detail}")

    def tamper_detected(self, detail: str, checked: int, sequence: int | None) -> None:
        body = json.dumps({
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"SECURITY: audit log tampering detected ({detail})",
                "severity": "critical",
                "source": "synapsepay-audit-verifier",
                "custom_details": {"detail": detail, "events_checked": checked, "sequence": sequence},
            },
        }).encode()
        request = urllib.request.Request(self.url, data=body, method="POST",
                                         headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(request, timeout=self.timeout).close()
        except (urllib.error.URLError, OSError) as exc:  # pragma: no cover - network dependent
            print(f"ALERT DELIVERY FAILED ({type(exc).__name__}): {detail}")
