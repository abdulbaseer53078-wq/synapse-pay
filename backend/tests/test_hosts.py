"""Step 14 gate: the breaker trips, half-opens, and the router prefers UP over DEGRADED."""
import pytest

from app.application.hosts import (HealthRegistry, HealthStatus, HostHealth, NoHealthyHostError,
                                   RestHostProvider)


def _provider(clock, history=None, **kwargs):
    calls = {"probe": 0}

    def probe():
        calls["probe"] += 1
        return 120

    provider = RestHostProvider("psp_upi_1", "UPI", probe=probe, clock=clock, **kwargs)
    for latency in history or []:
        provider.record_success(latency)
    return provider, calls


def _clock(start=1000.0):
    now = {"t": start}
    return now, (lambda: now["t"])


# --- the breaker ----------------------------------------------------------------------------------------

def test_five_consecutive_failures_trip_the_breaker():
    now, clock = _clock()
    provider, _ = _provider(clock, history=[120])

    for _ in range(4):
        provider.record_failure()
    assert provider.health().status == HealthStatus.UP  # four is not enough

    provider.record_failure()
    assert provider.health().status == HealthStatus.DOWN


def test_a_success_resets_the_streak():
    now, clock = _clock()
    provider, _ = _provider(clock, history=[120])
    for _ in range(4):
        provider.record_failure()
    provider.record_success(110)
    for _ in range(4):
        provider.record_failure()

    assert provider.health().status == HealthStatus.UP  # the streak restarted after the success


def test_the_breaker_half_opens_after_the_cool_off():
    now, clock = _clock()
    provider, calls = _provider(clock, history=[120], open_seconds=60)
    for _ in range(5):
        provider.record_failure()

    now["t"] += 59
    assert provider.health().status == HealthStatus.DOWN and calls["probe"] == 0

    now["t"] += 2  # past the cool-off: one probe decides
    assert provider.health().status == HealthStatus.UP and calls["probe"] == 1


def test_a_failed_probe_reopens_the_circuit():
    now, clock = _clock()
    state = {"fail": True}

    def probe():
        if state["fail"]:
            raise RuntimeError("still down")
        return 90

    provider = RestHostProvider("psp_upi_1", "UPI", probe=probe, clock=clock, open_seconds=60)
    provider.record_success(120)
    for _ in range(5):
        provider.record_failure()
    now["t"] += 61
    assert provider.health().status == HealthStatus.DOWN  # probe failed, re-opened

    state["fail"] = False
    now["t"] += 61
    assert provider.health().status == HealthStatus.UP


def test_a_slow_host_is_degraded_not_up():
    now, clock = _clock()
    provider, _ = _provider(clock, history=[4000], degraded_ms=1500)
    health = provider.health()
    assert health.status == HealthStatus.DEGRADED and health.latency_ms == 4000


# --- the registry ---------------------------------------------------------------------------------------

def _healthy(host_id, latency, rail="UPI"):
    now, clock = _clock()
    provider, _ = _provider(clock, history=[latency])
    provider.host_id, provider.rail_type = host_id, rail
    return provider


def test_the_router_picks_the_lowest_latency_up_host():
    registry = HealthRegistry([_healthy("psp_a", 300), _healthy("psp_b", 120), _healthy("psp_c", 900)])
    assert registry.get_healthy_host("UPI").host_id == "psp_b"


def test_up_beats_degraded_even_when_degraded_is_faster_on_paper():
    """DEGRADED means 'answering slowly'; a fast-looking number from a sick host is not a reason to use it."""
    now, clock = _clock()
    slow, _ = _provider(clock, history=[4000])   # DEGRADED
    slow.host_id = "psp_slow"
    fast, _ = _provider(clock, history=[500])    # UP
    fast.host_id = "psp_fast"

    registry = HealthRegistry([slow, fast])
    assert registry.get_healthy_host("UPI").host_id == "psp_fast"


def test_no_healthy_host_raises_rather_than_guessing():
    now, clock = _clock()
    dead, _ = _provider(clock, history=[120])
    for _ in range(5):
        dead.record_failure()
    with pytest.raises(NoHealthyHostError):
        HealthRegistry([dead]).get_healthy_host("UPI")


def test_card_health_comes_from_rust_and_is_merged():
    registry = HealthRegistry([_healthy("psp_a", 120)],
                              card_source=lambda: [{"host_id": "acquirer_a", "status": "UP", "latency_ms": 45},
                                                   {"host_id": "acquirer_b", "status": "DOWN"}])
    snapshot = {h.host_id: h for h in registry.snapshot()}
    assert snapshot["acquirer_a"].status == HealthStatus.UP and snapshot["acquirer_b"].rail_type == "CARD"
    assert snapshot["psp_a"].rail_type == "UPI"
    assert registry.get_healthy_host("CARD").host_id == "acquirer_a"


def test_an_unreachable_rust_endpoint_means_no_card_traffic():
    """Fail closed: unknown health is not healthy health."""
    def broken():
        raise ConnectionError("card service unreachable")

    registry = HealthRegistry([], card_source=broken)
    with pytest.raises(NoHealthyHostError):
        registry.get_healthy_host("CARD")
