"""Step 15 gate: rules pick the host deterministically, and only transient failures cascade."""
import pytest

from app.application.hosts import HealthRegistry, HealthStatus, NoHealthyHostError, RestHostProvider
from app.application.methods import MethodResult
from app.application.routing import InMemoryRules, RoutingEngine, RoutingRule, cascade


def _clock():
    now = {"t": 1000.0}
    return now, (lambda: now["t"])


def _host(host_id, latency, rail="UPI", failures=0):
    _, clock = _clock()
    provider = RestHostProvider(host_id, rail, clock=clock)
    provider.record_success(latency)
    for _ in range(failures):
        provider.record_failure()
    return provider


def _engine(rules, hosts):
    return RoutingEngine(InMemoryRules({"merch_1": rules}), HealthRegistry(hosts))


# --- rule selection -------------------------------------------------------------------------------------

def test_the_merchants_rule_decides_the_host():
    engine = _engine([RoutingRule("UPI", ("psp_a", "psp_b"))], [_host("psp_a", 200), _host("psp_b", 90)])

    decision = engine.route("merch_1", "UPI", 100_000)

    assert decision.host_id == "psp_a"  # rule order wins over latency, so routing stays predictable
    assert "UPI default rule" in decision.reason


def test_a_down_host_falls_through_to_the_next_preferred_host():
    engine = _engine([RoutingRule("UPI", ("psp_a", "psp_b"))],
                     [_host("psp_a", 200, failures=5), _host("psp_b", 400)])

    decision = engine.route("merch_1", "UPI", 100_000)

    assert decision.host_id == "psp_b"


def test_a_degraded_host_is_skipped_when_a_healthy_one_is_listed():
    engine = _engine([RoutingRule("UPI", ("psp_slow", "psp_fast"))],
                     [_host("psp_slow", 4000), _host("psp_fast", 300)])

    assert engine.route("merch_1", "UPI", 100_000).host_id == "psp_fast"


def test_an_amount_threshold_rule_wins_over_the_default():
    engine = _engine([RoutingRule("CARD", ("acquirer_default",)), RoutingRule("CARD", ("acquirer_premium",),
                                                                              min_amount=5_000_000)],
                     [_host("acquirer_default", 100, "CARD"), _host("acquirer_premium", 300, "CARD")])

    assert engine.route("merch_1", "CARD", 6_000_000).host_id == "acquirer_premium"
    assert engine.route("merch_1", "CARD", 100_000).host_id == "acquirer_default"


def test_no_healthy_host_raises_rather_than_sending_into_a_black_hole():
    engine = _engine([RoutingRule("UPI", ("psp_a",))], [_host("psp_a", 100, failures=5)])
    with pytest.raises(NoHealthyHostError):
        engine.route("merch_1", "UPI", 100_000)


def test_an_unknown_merchant_has_no_route():
    engine = _engine([], [_host("psp_a", 100)])
    with pytest.raises(NoHealthyHostError):
        engine.route("merch_unknown", "UPI", 100_000)


def test_the_decision_carries_the_reason_for_the_audit_log():
    engine = _engine([RoutingRule("UPI", ("psp_a",))], [_host("psp_a", 100)])
    assert engine.route("merch_1", "UPI", 100).to_dict()["reason"] == "UPI default rule; psp_a is UP"


def test_the_decision_carries_every_usable_host_in_preference_order():
    """The cascade needs the shortlist, not just the winner: a soft decline on the first host must reach the
    backup, and a DOWN host must not waste a hop on the way."""
    engine = _engine([RoutingRule("CARD", ("dead", "slow", "fast"))],
                     [_host("dead", 100, "CARD", failures=5), _host("slow", 4000, "CARD"),
                      _host("fast", 100, "CARD")])

    decision = engine.route("merch_1", "CARD", 100_000)

    assert decision.host_id == "fast"
    assert decision.candidates == ("fast", "slow")  # UP first, then the DEGRADED backup; DOWN dropped


def test_global_rules_apply_to_a_merchant_with_no_rules_of_its_own():
    """Operators can set a fleet-wide preference before per-merchant rules exist; "*" is that default."""
    engine = RoutingEngine(InMemoryRules({"*": [RoutingRule("CARD", ("acquirer_a",))]}),
                           HealthRegistry([_host("acquirer_a", 100, "CARD")]))

    assert engine.route("merch_unknown", "CARD", 100).host_id == "acquirer_a"


# --- cascade --------------------------------------------------------------------------------------------

def _soft(host):
    return MethodResult(status="FAILED", error={"error_code": "HOST_TIMEOUT", "error_message": "timeout",
                                                "error_category": "SOFT_DECLINE", "retryable": True})


def _hard(host):
    return MethodResult(status="FAILED", error={"error_code": "INSUFFICIENT_FUNDS", "error_message": "no funds",
                                                "error_category": "HARD_DECLINE", "retryable": False})


def _ok(host):
    return MethodResult(status="AUTHORIZED", method_reference=f"ref_{host}")


def test_a_transient_failure_cascades_to_the_backup():
    result, trail = cascade(["psp_a", "psp_b"], lambda host: _ok(host) if host == "psp_b" else _soft(host))

    assert result.status == "AUTHORIZED" and result.method_reference == "ref_psp_b"
    assert [step["host"] for step in trail] == ["psp_a", "psp_b"]
    assert trail[0]["retryable"] is True and trail[1]["retryable"] is False
    # Both facts the audit needs: who was asked, and why the attempt did not settle it.
    assert trail[0]["asked"] == "psp_a" and trail[0]["error_category"] == "SOFT_DECLINE"
    assert trail[1]["asked"] == "psp_b" and trail[1]["error_category"] is None


def test_a_hard_decline_does_not_cascade():
    """Retrying a declined card makes the customer wait for the same answer three times."""
    result, trail = cascade(["psp_a", "psp_b"], lambda host: _hard(host))

    assert result.status == "FAILED" and result.error["error_category"] == "HARD_DECLINE"
    assert len(trail) == 1


def test_cascade_stops_after_two_retries():
    hosts = ["a", "b", "c", "d", "e"]
    seen = []

    def attempt(host):
        seen.append(host)
        return _soft(host)

    result, trail = cascade(hosts, attempt)

    assert seen == ["a", "b", "c"]  # primary plus two retries
    assert result.status == "FAILED" and len(trail) == 3


def test_pending_without_a_next_action_cascades():
    """A provider that timed out after sending may have our money: try the backup so the payment still happens."""
    result, trail = cascade(["a", "b"], lambda host: MethodResult(status="PENDING") if host == "a" else _ok(host))
    assert result.method_reference == "ref_b" and len(trail) == 2


def test_pending_awaiting_the_customer_does_not_cascade():
    """UPI collect: their phone is ringing. A second collect would show them two PIN prompts."""
    waiting = MethodResult(status="PENDING", next_action={"type": "UPI_COLLECT", "url": "upi://pay?pa=a@b"})
    result, trail = cascade(["a", "b"], lambda host: waiting if host == "a" else _ok(host))

    assert result is waiting and len(trail) == 1
    assert trail[0]["retryable"] is False
