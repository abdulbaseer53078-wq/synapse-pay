"""Step 17.1: the endpoint Route 53 probes says UP only when this region can take a payment."""
from psycopg_pool import ConnectionPool

from app.application.hosts import HostHealth
from app.application.region_health import RegionHealth
from app.infrastructure.postgres_health import database_writable

CARD_UP = HostHealth("acquirer_a", "CARD", "UP")
CARD_DEGRADED = HostHealth("acquirer_a", "CARD", "DEGRADED")
CARD_DOWN = HostHealth("acquirer_a", "CARD", "DOWN")
UPI_UP = HostHealth("psp", "UPI", "UP")


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def region(writable=True, hosts=(CARD_UP,), clock=None, calls=None):
    def database():
        if calls is not None:
            calls.append(1)
        if isinstance(writable, Exception):
            raise writable
        return writable
    return RegionHealth(database, lambda: list(hosts), ttl=5.0, clock=clock or Clock())


def test_up_needs_a_writable_database_and_a_usable_acquirer():
    assert region().is_up()
    assert region(hosts=[CARD_DOWN, CARD_DEGRADED]).is_up(), "a degraded acquirer still takes payments"
    assert not region(writable=False).is_up(), "an unpromoted standby (read-only replica) must stay out of DNS"
    assert not region(hosts=[CARD_DOWN]).is_up()
    assert not region(hosts=[UPI_UP]).is_up(), "UPI alone doesn't make a card network region healthy"
    assert not region(hosts=[]).is_up(), "no health snapshot yet: fail closed"
    assert not region(writable=ConnectionError("db unreachable")).is_up()


def test_the_answer_is_cached_so_probes_dont_hit_the_database():
    clock, calls = Clock(), []
    health = region(clock=clock, calls=calls)
    for _ in range(50):  # Route 53 probes from many checkers at once
        health.is_up()
    assert len(calls) == 1
    clock.now = 5.0
    health.is_up()
    assert len(calls) == 2, "re-checked once the cache expires"


def test_the_endpoint_says_only_up_or_down(client):
    client.app.state.region_health = region()
    r = client.get("/health/region")
    assert (r.status_code, r.json()) == (200, {"status": "UP"})
    assert r.headers["cache-control"] == "no-store"

    client.app.state.region_health = region(writable=False)
    r = client.get("/health/region")
    assert (r.status_code, r.json()) == (503, {"status": "DOWN"}), "nothing about which component failed"


def test_liveness_is_independent_of_region_health(client):
    client.app.state.region_health = region(writable=False)  # an unpromoted standby
    assert client.get("/health/live").status_code == 200, "the load balancer must not kill standby tasks"
    assert client.get("/health/region").status_code == 503


def test_the_database_check_reports_a_primary_as_writable(database_url):
    with ConnectionPool(database_url, min_size=1, max_size=1) as pool:
        assert database_writable(pool)() is True
