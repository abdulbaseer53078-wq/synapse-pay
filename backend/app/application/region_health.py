"""Region health for the global load balancer (Stage 4, Step 17.1).

Route 53 checks every region's `/health/region` every 10 s and fails a region after 3 misses. "Healthy" means
this region can take a payment right now:

* its database is the writable primary: a standby region whose Aurora secondary hasn't been promoted reports
  DOWN, so DNS only moves traffic there once it can actually write, and there is never more than one writer;
* card-service has at least one acquirer that can take traffic (the cached snapshot the router already reads).

The answer is cached for `ttl` seconds behind a lock: Route 53 probes from many checkers at once, and that must
not turn into many database queries.
"""
import threading
import time
from typing import Callable

from app.application.hosts import HostHealth


class RegionHealth:
    def __init__(self, database_writable: Callable[[], bool], hosts: Callable[[], list[HostHealth]],
                 ttl: float = 5.0, clock: Callable[[], float] = time.monotonic):
        self._database_writable = database_writable
        self._hosts = hosts
        self._ttl = ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._checked_at: float | None = None
        self._up = False

    def is_up(self) -> bool:
        with self._lock:  # one check at a time; everyone else gets the fresh answer
            now = self._clock()
            if self._checked_at is None or now - self._checked_at >= self._ttl:
                self._up = self._check()
                self._checked_at = now
            return self._up

    def _check(self) -> bool:
        try:
            if not self._database_writable():
                return False
            return any(h.rail_type == "CARD" and h.usable for h in self._hosts())
        except Exception:  # anything we can't confirm is DOWN: a wrong UP strands payments in a dead region
            return False
