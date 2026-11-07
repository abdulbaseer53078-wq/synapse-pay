"""Host health across two runtimes (Stage 3, Step 14).

Cards are connected in Rust (`card-service` → `host-connector`), UPI and wallets in Python. Only the owner of a
socket can honestly say whether it is working, so:

* Rust owns the card circuit breakers. Python polls `GET /internal/v1/hosts/health` and never guesses.
* Python owns the PSP breakers, because it holds those connections itself.
* `HealthRegistry` merges both into the single view the routing engine (Step 15) reads.

Failure is closed: if the Rust health endpoint cannot be reached, every card host is reported DOWN. Routing a
card to a host whose health is unknown is how you turn one outage into two.
"""
import time
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Callable, Protocol


class HealthStatus(StrEnum):
    UP = "UP"
    DEGRADED = "DEGRADED"  # answering, but slowly: avoid it when a faster host is available
    DOWN = "DOWN"


class NoHealthyHostError(Exception):
    """No host on this rail can take traffic. The caller decides whether to fail or queue."""


@dataclass(frozen=True)
class HostHealth:
    host_id: str
    rail_type: str  # CARD | UPI | WALLET
    status: str
    latency_ms: int | None = None
    last_error_at: datetime | None = None

    @property
    def usable(self) -> bool:
        return self.status in (HealthStatus.UP, HealthStatus.DEGRADED)


class HostHealthSource(Protocol):
    """The Rust endpoint, as Python sees it: a list of dicts, or an exception if it is unreachable."""

    def __call__(self) -> list[dict]: ...


class RestHostProvider:
    """One PSP connection, owned by Python. Trips after N consecutive failures, half-opens after a cool-off.

    Latency is a rolling window, not an all-time average: an acquirer that got slow ten minutes ago should lose
    traffic now, and an all-time mean would hide it for hours.
    """

    def __init__(self, host_id: str, rail_type: str, probe: Callable[[], int] | None = None,
                 clock: Callable[[], float] = time.time, failure_threshold: int = 5,
                 open_seconds: float = 60, degraded_ms: int = 1500, window: int = 1000):
        self.host_id = host_id
        self.rail_type = rail_type
        self.probe = probe  # returns latency_ms, raises on failure; used to half-open and to sample
        self.clock = clock
        self.failure_threshold = failure_threshold
        self.open_seconds = open_seconds
        self.degraded_ms = degraded_ms
        self._latencies: deque[int] = deque(maxlen=window)
        self._failures = 0
        self._open_until = 0.0
        self._last_error: datetime | None = None

    # --- what the caller reports after each transaction ------------------------------------------------

    def record_success(self, latency_ms: int) -> None:
        self._latencies.append(latency_ms)
        self._failures = 0
        self._open_until = 0.0

    def record_failure(self) -> None:
        self._failures += 1
        self._last_error = datetime.now(UTC)
        if self._failures >= self.failure_threshold:
            self._open_until = self.clock() + self.open_seconds

    # --- what the registry asks -----------------------------------------------------------------------

    def health(self) -> HostHealth:
        now = self.clock()
        if self._open_until:
            if now < self._open_until:
                return self._down()
            if not self._half_open():
                return self._down()
        average = int(sum(self._latencies) / len(self._latencies)) if self._latencies else None
        if average is None:
            return HostHealth(self.host_id, self.rail_type, HealthStatus.DOWN, None, self._last_error)
        status = HealthStatus.UP if average < self.degraded_ms else HealthStatus.DEGRADED
        return HostHealth(self.host_id, self.rail_type, status, average, self._last_error)

    def _half_open(self) -> bool:
        """One probe decides. Success closes the circuit; failure re-opens it for another cool-off."""
        if self.probe is None:
            self._failures = 0
            self._open_until = 0.0
            return True
        try:
            self.record_success(self.probe())
            return True
        except Exception:
            self._open_until = self.clock() + self.open_seconds
            self._last_error = datetime.now(UTC)
            return False

    def _down(self) -> HostHealth:
        return HostHealth(self.host_id, self.rail_type, HealthStatus.DOWN, None, self._last_error)


class HealthRegistry:
    """The one view the router reads: Python's PSPs plus whatever Rust reports about its card hosts."""

    def __init__(self, local: list[RestHostProvider], card_source: HostHealthSource | None = None):
        self.local = local
        self.card_source = card_source

    def snapshot(self) -> list[HostHealth]:
        return self._merge()

    def _merge(self) -> list[HostHealth]:
        health = [provider.health() for provider in self.local]
        if self.card_source is not None:
            try:
                reported = self.card_source()
            except Exception:
                # Fail closed: we cannot see the sockets, so we must not pretend they are working.
                health.extend(self._card_hosts_down())
            else:
                health.extend(HostHealth(item["host_id"], "CARD", item["status"], item.get("latency_ms"))
                              for item in reported)
        return health

    def _card_hosts_down(self) -> list[HostHealth]:
        return [HostHealth(provider.host_id, "CARD", HealthStatus.DOWN) for provider in self.local
                if provider.rail_type == "CARD"]

    def get_healthy_host(self, rail_type: str) -> HostHealth:
        """UP before DEGRADED, then lowest latency. A slow host only wins when nothing faster is up."""
        candidates = [h for h in self._merge() if h.rail_type == rail_type and h.usable]
        if not candidates:
            raise NoHealthyHostError(f"no healthy {rail_type} host is available")
        return min(candidates, key=lambda h: (h.status != HealthStatus.UP, h.latency_ms or 0))
