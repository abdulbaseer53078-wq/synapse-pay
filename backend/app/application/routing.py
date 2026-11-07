"""Rule-based routing and cascade (Stage 3, Step 15).

Two jobs, kept apart on purpose:

* `RoutingEngine` picks a host from merchant rules and live health. It makes no network calls and has no
  randomness, so a merchant asking "why did this go to Acquirer A?" gets the rule that fired, not a shrug.
* `cascade` retries a *transient* failure on the next host. It stops dead at a hard decline: retrying a declined
  card is how a customer gets charged twice or gets a second decline for the same money.

Cards are the exception to host choice: Rust owns the sockets and the breakers, so for CARD the engine emits the
*preferred order* and lets the card service pick inside it. Python decides the shortlist, Rust decides the link.
"""
from dataclasses import dataclass, field
from typing import Callable, Iterable, Protocol

from app.application.hosts import HealthRegistry, HealthStatus, NoHealthyHostError
from app.application.methods import MethodResult

MAX_RETRIES = 2  # one primary plus two backups: five hops is a 30-second failure the customer remembers


@dataclass(frozen=True)
class RoutingRule:
    payment_method: str
    preferred_hosts: tuple[str, ...]
    min_amount: int | None = None  # minor units; a rule only applies at or above this
    note: str = ""

    def applies(self, method: str, amount: int) -> bool:
        return self.payment_method == method and (self.min_amount is None or amount >= self.min_amount)

    def describe(self, amount: int) -> str:
        if self.min_amount is None:
            return f"{self.payment_method} default rule"
        return f"{self.payment_method} over {self.min_amount} (minor units)"


@dataclass(frozen=True)
class RoutingDecision:
    host_id: str
    rail_type: str
    reason: str  # the rule and the health that justified it — this goes into the audit trail
    candidates: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"host_id": self.host_id, "rail_type": self.rail_type, "reason": self.reason,
                "candidates": list(self.candidates)}


class RuleStore(Protocol):
    def rules_for(self, merchant_id: str) -> list[RoutingRule]: ...


class InMemoryRules:
    """The shape the database table will have: merchant → rules. Step 15 reads it through the same protocol."""

    def __init__(self, rules: dict[str, list[RoutingRule]] | None = None):
        self._rules = rules or {}

    def rules_for(self, merchant_id: str) -> list[RoutingRule]:
        return self._rules.get(merchant_id, [])


class RoutingEngine:
    def __init__(self, rules: RuleStore, health: HealthRegistry):
        self.rules = rules
        self.health = health

    def route(self, merchant_id: str, method: str, amount: int) -> RoutingDecision:
        available = {h.host_id: h for h in self.health.snapshot()}
        for rule in self._ordered(merchant_id, method, amount):
            chosen = self._first_healthy(rule, available)
            if chosen is not None:
                return RoutingDecision(chosen.host_id, chosen.rail_type,
                                       f"{rule.describe(amount)}; {chosen.host_id} is {chosen.status}",
                                       rule.preferred_hosts)
        raise NoHealthyHostError(f"no healthy host for {method} at this merchant")

    def _ordered(self, merchant_id: str, method: str, amount: int) -> list[RoutingRule]:
        """Most specific first: an amount threshold beats the default rule for the same method."""
        matching = [r for r in self.rules.rules_for(merchant_id) if r.applies(method, amount)]
        matching.sort(key=lambda r: (r.min_amount is None, -(r.min_amount or 0)))
        return matching

    @staticmethod
    def _first_healthy(rule: RoutingRule, available: dict):
        """DOWN is skipped. DEGRADED is used only when nothing better in this rule is left."""
        candidates = [available[h] for h in rule.preferred_hosts if h in available and available[h].usable]
        if not candidates:
            return None
        up = [h for h in candidates if h.status == HealthStatus.UP]
        return (up or candidates)[0]


def cascade(hosts: Iterable[str], attempt: Callable[[str], MethodResult],
            max_retries: int = MAX_RETRIES) -> tuple[MethodResult, list[dict]]:
    """Try hosts in order until a non-retryable answer. Returns the result and the trail for the audit log.

    `attempt` performs one transaction against one host. A retryable failure (timeout, soft decline, provider
    5xx) moves to the next host; anything else stops immediately, because a hard decline will be the same answer
    from every acquirer and the customer should not wait for three of them.
    """
    trail: list[dict] = []
    last: MethodResult | None = None
    for index, host in enumerate(list(hosts)[: max_retries + 1]):
        result = attempt(host)
        last = result
        retryable = bool(result.error and result.error.get("retryable")) or result.status == "PENDING"
        trail.append({"host": host, "status": result.status, "retryable": retryable,
                      "error": (result.error or {}).get("error_code")})
        if not retryable:
            return result, trail
    return last or MethodResult(status="FAILED"), trail
