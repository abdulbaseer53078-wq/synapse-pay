"""Step 20 on the edge: only signed, bound, forward-moving rules are trusted, and only until they expire."""
import json
import logging

import pytest

from edge_node import db
from edge_node.rules import (RulesExpired, RulesMissing, RulesRejected, RulesTampered, accept, current_rules,
                             refresh)


@pytest.fixture
def conn(cfg):
    c = db.connect(cfg.db_path)
    db.migrate(c)
    yield c
    c.close()


def test_signed_rules_for_this_edge_are_installed(conn, cfg, cloud, clock):
    with pytest.raises(RulesMissing):
        current_rules(conn, cfg, clock())
    accept(conn, cloud.signed_rules(), cfg, clock())
    rules = current_rules(conn, cfg, clock())
    assert (rules.rules_version, rules.offline_limits.per_transaction) == (1, 200_000)
    assert rules.terminals == {"TERM-1", "TERM-2"}


def test_forged_or_misdirected_rules_are_refused(conn, cfg, cloud, clock):
    forged = {**cloud.signed_rules(), "offline_limits": {"per_transaction": 10**9, "per_day": 10**9,
                                                        "max_age_minutes": 4320}}
    with pytest.raises(RulesRejected, match="signature"):
        accept(conn, forged, cfg, clock())
    with pytest.raises(RulesRejected, match="another edge"):
        accept(conn, cloud.signed_rules(edge_node_id="someone-else"), cfg, clock())
    with pytest.raises(RulesMissing):
        current_rules(conn, cfg, clock())


def test_versions_only_move_forward(conn, cfg, cloud, clock):
    cloud.version = 3
    accept(conn, cloud.signed_rules(), cfg, clock())
    cloud.version = 2
    with pytest.raises(RulesRejected, match="older"):
        accept(conn, cloud.signed_rules(), cfg, clock())
    clock.advance(hours=1)
    cloud.version = 3
    accept(conn, cloud.signed_rules(), cfg, clock())  # same version, re-issued later: extends the expiry
    assert current_rules(conn, cfg, clock()).rules_version == 3


def test_rules_expire_after_72_hours_and_a_rewound_clock_cannot_revive_them(conn, cfg, cloud, clock):
    accept(conn, cloud.signed_rules(), cfg, clock())
    start = clock()
    clock.advance(hours=71, minutes=59)
    current_rules(conn, cfg, clock())
    clock.advance(minutes=2)
    with pytest.raises(RulesExpired):
        current_rules(conn, cfg, clock())
    clock.t = start  # someone winds the clock back
    with pytest.raises(RulesExpired):
        current_rules(conn, cfg, clock())


def test_editing_the_cached_rules_is_detected(conn, cfg, cloud, clock):
    accept(conn, cloud.signed_rules(), cfg, clock())
    body = json.loads(conn.execute("SELECT body_json FROM rules_cache").fetchone()[0])
    body["offline_limits"]["per_transaction"] = 10**9
    conn.execute("UPDATE rules_cache SET body_json = ?", (json.dumps(body),))
    with pytest.raises(RulesTampered):
        current_rules(conn, cfg, clock())


def test_a_failed_fetch_keeps_the_last_good_rules(conn, cfg, cloud, clock, caplog):
    accept(conn, cloud.signed_rules(), cfg, clock())
    cloud.reachable = False
    with caplog.at_level(logging.WARNING):
        assert refresh(conn, cfg, cloud.fetch_rules, clock()) is None
    assert "CLOUD_SYNC_FAILED" in caplog.text
    assert current_rules(conn, cfg, clock()).rules_version == 1
