"""Fallback observability (Stage 4, Step 18): trace IDs, the standard failover event, and failover metrics.

Every runtime (SDK, Python, Rust) emits the same failover event, so one log query aggregates all of them:

    {"event": "FAILOVER_TRIGGERED", "layer": "SDK|ROUTING|HOST|CLOUD_REGION", "trace_id": "...",
     "from_path": "acquirer_a", "to_path": "acquirer_b", "reason": "SOFT_DECLINE", "latency_lost_ms": 450}

Logging is 100% for failovers and errors and SUCCESS_LOG_RATE (1%) for plain successes. Metrics are served on
their own port (METRICS_PORT), never through the public API.
"""
import json
import logging
import random
import re
import uuid

from prometheus_client import Counter, Gauge, Histogram

log = logging.getLogger("synapsepay.events")

SUCCESS_LOG_RATE = 0.01
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")

FAILOVERS = Counter("failover_count", "Failovers, by layer and reason", ["layer", "reason"])
FALLBACK_LATENCY = Histogram("fallback_latency_seconds", "Time spent on the attempt that failed before failing over",
                             ["layer"], buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20))
CASCADES = Counter("cascade", "Transactions that failed over, by whether a backup answered", ["outcome"])
HOST_ATTEMPTS = Counter("host_attempts", "Attempts per host: answered (approved or a final decline) or failed",
                        ["host", "outcome"])
HOST_UP = Gauge("host_up", "1 if the host can take traffic, by host and rail", ["host", "rail"])
# PR 10. Labelled by the route's template (/api/v1/transactions/{transaction_id}/refund), never the raw path, so one
# metric series per endpoint rather than one per transaction id.
HTTP_LATENCY = Histogram("http_request_duration_seconds", "API request latency", ["method", "route", "status"],
                         buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20))
# A write the ledger refused because it didn't balance, or an edit to a row that may not change: a code bug or an
# attack, never normal. Paired with the database-read gauges in db_metrics, which catch what bypasses the code.
LEDGER_INTEGRITY_REFUSED = Counter("synapse_ledger_imbalance", "Ledger writes refused for breaking an invariant",
                                   ["reason"])


def trace_id_from(header: str | None) -> str:
    """The caller's trace id as 32 lowercase hex digits (the W3C / OpenTelemetry form). A UUID is accepted with or
    without dashes. Anything else, including all zeros, gets a fresh id: it's caller-supplied text that ends up
    in logs, and a shared id would merge unrelated payments into one trace."""
    candidate = (header or "").strip().lower().replace("-", "")
    if _TRACE_ID.match(candidate) and candidate.strip("0"):
        return candidate
    return uuid.uuid4().hex


def emit(event: dict) -> None:
    log.warning(json.dumps(event, separators=(",", ":")))


def failover(layer: str, trace_id: str, from_path: str, to_path: str, reason: str, latency_lost_ms: int) -> None:
    FAILOVERS.labels(layer, reason).inc()
    FALLBACK_LATENCY.labels(layer).observe(latency_lost_ms / 1000)
    emit({"event": "FAILOVER_TRIGGERED", "layer": layer, "trace_id": trace_id, "from_path": from_path,
          "to_path": to_path, "reason": reason, "latency_lost_ms": latency_lost_ms})


def failover_reason(attempt: dict) -> str:
    """Why a cascade attempt was abandoned, in the shared vocabulary."""
    if attempt.get("error_category") == "SOFT_DECLINE":
        return "SOFT_DECLINE"
    if attempt.get("status") == "PENDING":
        return "TIMEOUT"  # sent, no answer
    return "SYSTEM_ERROR"


def record_cascade(trail: list[dict], trace_id: str) -> None:
    """Metrics and failover events for one routed transaction (the attempt trail from routing.cascade)."""
    for attempt in trail:
        HOST_ATTEMPTS.labels(attempt["host"], "failed" if attempt["retryable"] else "answered").inc()
    for failed, nxt in zip(trail, trail[1:]):
        failover("ROUTING", trace_id, failed["host"], nxt["asked"], failover_reason(failed), failed.get("elapsed_ms", 0))
    if len(trail) > 1:
        CASCADES.labels("exhausted" if trail[-1]["retryable"] else "recovered").inc()


def publish_health(hosts) -> None:
    for host in hosts:
        HOST_UP.labels(host.host_id, host.rail_type).set(1 if host.usable else 0)


def log_outcome(trace_id: str, response: dict) -> None:
    """One line per finished transaction: always for failures and unknown outcomes, 1% of successes."""
    status = response.get("status")
    if status in ("FAILED", "PENDING") or random.random() < SUCCESS_LOG_RATE:
        error = response.get("error") or {}
        emit({"event": "TRANSACTION_FINISHED", "trace_id": trace_id, "transaction_id": response.get("transaction_id"),
              "status": status, "error_code": error.get("error_code"), "error_category": error.get("error_category")})
