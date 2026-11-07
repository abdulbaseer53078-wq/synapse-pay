"""Step 14.8: the poller's cached snapshot, and failing closed before the first poll."""
import pytest

from app.application.hosts import (CachedHealth, HealthRegistry, HealthStatus, NoHealthyHostError,
                                   RestHostProvider)


def _provider(host_id, latency=100, rail="CARD"):
    provider = RestHostProvider(host_id, rail)
    provider.record_success(latency)
    return provider


def _monitor(cards, card_host_ids=()):
    return CachedHealth(HealthRegistry([], card_source=lambda: cards, card_host_ids=card_host_ids))


def test_a_successful_poll_fills_the_cache():
    monitor = _monitor([{"host_id": "acquirer_a", "status": "UP", "latency_ms": 45}])

    monitor.refresh()

    assert [(h.host_id, h.status) for h in monitor.snapshot()] == [("acquirer_a", HealthStatus.UP)]
    assert monitor.get_healthy_host("CARD").host_id == "acquirer_a"


def test_a_failed_poll_reports_the_known_card_hosts_down():
    """Rust unreachable: we cannot see the sockets, so every card host is named DOWN — not omitted.

    Naming them matters: an operator looking at the dashboard needs to see `acquirer_a DOWN`, and a router
    reading an empty rail would fail with the same 503 but for the wrong reason.
    """
    def broken():
        raise TimeoutError("card service did not answer")

    monitor = CachedHealth(HealthRegistry([], card_source=broken, card_host_ids=("acquirer_a", "acquirer_b")))
    monitor.refresh()

    assert [(h.host_id, h.status) for h in monitor.snapshot()] == [
        ("acquirer_a", HealthStatus.DOWN), ("acquirer_b", HealthStatus.DOWN)]
    with pytest.raises(NoHealthyHostError):
        monitor.get_healthy_host("CARD")


def test_the_cache_is_empty_until_the_first_poll():
    """Fail closed by construction: a router that starts before the poller routes nothing, rather than
    optimistically assuming everything is fine."""
    monitor = _monitor([{"host_id": "acquirer_a", "status": "UP", "latency_ms": 45}])
    assert monitor.snapshot() == []
    with pytest.raises(NoHealthyHostError):
        monitor.get_healthy_host("CARD")


def test_a_dead_card_host_is_skipped_for_a_live_one():
    monitor = _monitor([{"host_id": "acquirer_a", "status": "DOWN"},
                        {"host_id": "acquirer_b", "status": "UP", "latency_ms": 80}])
    monitor.refresh()
    assert monitor.get_healthy_host("CARD").host_id == "acquirer_b"


def test_the_router_reads_the_cache_not_the_source():
    """The poller is the only thing that talks to Rust; the transaction path must not."""
    calls = {"n": 0}

    def source():
        calls["n"] += 1
        return [{"host_id": "acquirer_a", "status": "UP", "latency_ms": 30}]

    monitor = CachedHealth(HealthRegistry([], card_source=source))
    monitor.refresh()
    for _ in range(5):
        monitor.get_healthy_host("CARD")

    assert calls["n"] == 1


def test_psp_health_is_merged_into_the_same_snapshot():
    monitor = CachedHealth(HealthRegistry([_provider("psp_upi_1", rail="UPI")],
                                          card_source=lambda: [{"host_id": "acquirer_a", "status": "UP",
                                                                "latency_ms": 45}]))
    monitor.refresh()
    rails = {h.rail_type for h in monitor.snapshot()}
    assert rails == {"CARD", "UPI"}
