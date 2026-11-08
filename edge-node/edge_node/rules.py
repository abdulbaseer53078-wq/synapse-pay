"""Step 20: the offline rules, as the edge holds them.

A rule set is accepted only if:
* the cloud's rules key (pinned at registration) signed it;
* it names this edge and this merchant, so one edge's rules can't be replayed onto another;
* it isn't older than what we hold: versions only move forward, and the same version only with a later issued_at.

It is trusted only until its signed expires_at (72 h). "Now" is never earlier than the latest time this edge has
seen (its own clock or a rule set's issued_at): winding the clock back can't make expired rules valid again.
The rules are re-verified every time they are read, so editing the SQLite file breaks them rather than loosening
them. A failed fetch keeps the last good rule set and logs CLOUD_SYNC_FAILED.
"""
import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable

from edge_node import crypto
from edge_node.config import EdgeConfig

log = logging.getLogger("edge_node.rules")


class RulesMissing(Exception):
    """No rule set yet: offline payments are refused until the first fetch succeeds."""


class RulesExpired(Exception):
    """The rule set is past its expiry: offline payments are refused until the cloud is reachable again."""


class RulesTampered(Exception):
    """The stored rule set no longer matches its signature: someone edited the file."""


class RulesRejected(Exception):
    """A fetched rule set we refuse to install (bad signature, wrong edge, older version)."""


@dataclass(frozen=True)
class OfflineLimits:
    per_transaction: int
    per_day: int
    max_age_minutes: int


@dataclass(frozen=True)
class Rules:
    rules_version: int
    issued_at: datetime
    expires_at: datetime
    offline_limits: OfflineLimits
    terminals: frozenset[str]
    routing_rules: dict
    fraud_thresholds: dict
    token_index: dict


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _check(body: dict, cfg: EdgeConfig) -> Rules:
    """Signature and binding. Raises RulesRejected."""
    if not crypto.verify(cfg.rules_public_key_pem, body):
        raise RulesRejected("signature does not verify against the pinned rules key")
    if (body.get("edge_node_id"), body.get("merchant_id")) != (cfg.edge_node_id, cfg.merchant_id):
        raise RulesRejected("rule set is for another edge node or merchant")
    limits = body["offline_limits"]
    return Rules(
        rules_version=int(body["rules_version"]), issued_at=_time(body["issued_at"]),
        expires_at=_time(body["expires_at"]),
        offline_limits=OfflineLimits(int(limits["per_transaction"]), int(limits["per_day"]),
                                     int(limits["max_age_minutes"])),
        terminals=frozenset(body.get("terminals") or []), routing_rules=body.get("routing_rules") or {},
        fraud_thresholds=body.get("fraud_thresholds") or {}, token_index=body.get("token_index") or {})


def _raise_high_water(conn: sqlite3.Connection, t: datetime) -> datetime:
    """Records `t` if it is later than anything seen; returns the high-water mark."""
    row = conn.execute("SELECT high_water FROM clock_guard WHERE singleton = 1").fetchone()
    current = _time(row["high_water"]) if row else None
    if current is None or t > current:
        conn.execute("INSERT INTO clock_guard (singleton, high_water) VALUES (1, ?)"
                     " ON CONFLICT (singleton) DO UPDATE SET high_water = excluded.high_water", (_iso(t),))
        return t
    return current


def accept(conn: sqlite3.Connection, body: dict, cfg: EdgeConfig, now: datetime) -> Rules:
    """Installs a fetched rule set. Raises RulesRejected; the stored rules are then unchanged."""
    rules = _check(body, cfg)
    conn.execute("BEGIN IMMEDIATE")
    try:
        held = conn.execute("SELECT rules_version, issued_at FROM rules_cache"
                            " ORDER BY rules_version DESC LIMIT 1").fetchone()
        if held and (rules.rules_version, rules.issued_at) <= (held["rules_version"], _time(held["issued_at"])):
            if (rules.rules_version, rules.issued_at) < (held["rules_version"], _time(held["issued_at"])):
                raise RulesRejected(f"rule set v{rules.rules_version} is older than the v{held['rules_version']} held")
            conn.execute("COMMIT")
            return rules  # the same set again: nothing to do
        conn.execute("INSERT OR REPLACE INTO rules_cache (rules_version, issued_at, body_json, fetched_at)"
                     " VALUES (?, ?, ?, ?)", (rules.rules_version, _iso(rules.issued_at), json.dumps(body), _iso(now)))
        _raise_high_water(conn, max(now, rules.issued_at))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return rules


def current_rules(conn: sqlite3.Connection, cfg: EdgeConfig, now: datetime) -> Rules:
    """The rule set to enforce right now. Raises RulesMissing, RulesTampered or RulesExpired."""
    row = conn.execute("SELECT body_json FROM rules_cache ORDER BY rules_version DESC LIMIT 1").fetchone()
    if row is None:
        raise RulesMissing("no offline rules yet")
    try:
        rules = _check(json.loads(row["body_json"]), cfg)
    except (RulesRejected, ValueError, KeyError, TypeError) as exc:
        raise RulesTampered(f"stored rules fail verification: {exc}") from exc
    effective = _raise_high_water(conn, now)  # a clock wound back still sees the latest time we've seen
    if effective >= rules.expires_at:
        raise RulesExpired(f"rules v{rules.rules_version} expired at {_iso(rules.expires_at)}")
    return rules


def refresh(conn: sqlite3.Connection, cfg: EdgeConfig, fetch: Callable[[], dict], now: datetime) -> Rules | None:
    """Fetches and installs the latest rules. On any failure keeps the last good set; returns None."""
    try:
        return accept(conn, fetch(), cfg, now)
    except Exception as exc:  # network, HTTP, rejection: all mean "keep what we have"
        log.warning("CLOUD_SYNC_FAILED: rules not refreshed (%s: %s); keeping the last good rule set",
                    type(exc).__name__, exc)
        return None
