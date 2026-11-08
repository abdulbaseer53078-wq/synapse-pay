"""Step 18, Python side: one trace id from the SDK through the cascade, card-service and the audit log; the
standard failover event; and the failover metrics."""
import json
import logging
from uuid import uuid4

from prometheus_client import REGISTRY

from app.application import observability
from app.application.hosts import HostHealth
from app.application.observability import trace_id_from
from app.application.transactions import parse_public_id
from card_sim import encrypted_card
# The scripted two-host card service and its fixtures: psp_1 soft-declines, psp_2 approves.
from test_cascade_e2e import _payload, cards, ready, routed_client, routed_settings  # noqa: F401

SDK_TRACE = "4bf92f35-77b3-4da6-a3ce-929d0e0e4736"
SDK_TRACE_HEX = "4bf92f3577b34da6a3ce929d0e0e4736"


def metric(name, **labels):
    return REGISTRY.get_sample_value(name, labels) or 0.0


def pay(client, ready, merchant, headers=None):
    body = {
        "idempotency_key": str(uuid4()), "amount": 50_000, "currency": "INR", "payment_method": "CARD",
        "method_details": {"encrypted_card_data": encrypted_card(), "card_expiry": "08/28", "card_network": "VISA"},
        "terminal_id": ready["terminal_id"], "merchant_id": str(merchant),
    }
    return client.post("/api/v1/transactions", json=body,
                       headers={"x-terminal-id": ready["terminal_id"], **(headers or {})})


def events(caplog, name):
    return [json.loads(r.getMessage()) for r in caplog.records
            if r.name == "synapsepay.events" and json.loads(r.getMessage())["event"] == name]


def test_trace_ids_are_normalised_or_replaced():
    assert trace_id_from(SDK_TRACE) == SDK_TRACE_HEX
    assert trace_id_from(SDK_TRACE_HEX.upper()) == SDK_TRACE_HEX
    for bad in (None, "", "0" * 32, "00000000-0000-0000-0000-000000000000", "abc", "x" * 32,
                SDK_TRACE_HEX + "\n{\"event\":\"forged\"}"):
        fresh = trace_id_from(bad)
        assert len(fresh) == 32 and fresh.strip("0") and fresh != SDK_TRACE_HEX, repr(bad)
    assert trace_id_from(None) != trace_id_from(None), "every untraced request gets its own id"


def test_one_trace_id_follows_a_cascaded_payment_everywhere(routed_client, ready, merchant, cards, db, caplog):
    before = {
        "failovers": metric("failover_count_total", layer="ROUTING", reason="SOFT_DECLINE"),
        "recovered": metric("cascade_total", outcome="recovered"),
        "psp_1_failed": metric("host_attempts_total", host="psp_1", outcome="failed"),
        "psp_2_answered": metric("host_attempts_total", host="psp_2", outcome="answered"),
        "latency_count": metric("fallback_latency_seconds_count", layer="ROUTING"),
    }
    with caplog.at_level(logging.WARNING, logger="synapsepay.events"):
        response = pay(routed_client, ready, merchant, {"X-Trace-Id": SDK_TRACE})

    assert response.status_code == 201, response.text
    assert response.headers["x-trace-id"] == SDK_TRACE_HEX, "returned so the merchant can quote it"
    # Card-service received it on both attempts (it logs it beside the STAN and RRN).
    assert [r.trace_id for r in cards.received] == [SDK_TRACE_HEX, SDK_TRACE_HEX]
    # The audit log row for the payment carries it.
    assert _payload(db, parse_public_id(response.json()["transaction_id"], "txn_"))["trace_id"] == SDK_TRACE_HEX

    [event] = events(caplog, "FAILOVER_TRIGGERED")
    latency = event.pop("latency_lost_ms")
    assert event == {"event": "FAILOVER_TRIGGERED", "layer": "ROUTING", "trace_id": SDK_TRACE_HEX,
                     "from_path": "psp_1", "to_path": "psp_2", "reason": "SOFT_DECLINE"}
    assert isinstance(latency, int) and latency >= 0

    assert metric("failover_count_total", layer="ROUTING", reason="SOFT_DECLINE") == before["failovers"] + 1
    assert metric("cascade_total", outcome="recovered") == before["recovered"] + 1
    assert metric("host_attempts_total", host="psp_1", outcome="failed") == before["psp_1_failed"] + 1
    assert metric("host_attempts_total", host="psp_2", outcome="answered") == before["psp_2_answered"] + 1
    assert metric("fallback_latency_seconds_count", layer="ROUTING") == before["latency_count"] + 1


def test_an_untraced_request_gets_its_own_trace_id(routed_client, ready, merchant):
    first, second = pay(routed_client, ready, merchant), pay(routed_client, ready, merchant)
    assert first.headers["x-trace-id"] != second.headers["x-trace-id"]
    assert first.headers["x-trace-id"].strip("0"), "never the shared all-zeros id"


def test_failures_are_always_logged_successes_are_sampled(caplog, monkeypatch):
    with caplog.at_level(logging.WARNING, logger="synapsepay.events"):
        monkeypatch.setattr(observability.random, "random", lambda: 0.5)  # outside the 1% sample
        observability.log_outcome("t1", {"status": "CAPTURED", "transaction_id": "txn_a"})
        observability.log_outcome("t2", {"status": "FAILED", "transaction_id": "txn_b",
                                         "error": {"error_code": "ISSUER_DECLINED", "error_category": "HARD_DECLINE"}})
        observability.log_outcome("t3", {"status": "PENDING", "transaction_id": "txn_c"})
        monkeypatch.setattr(observability.random, "random", lambda: 0.001)  # inside it
        observability.log_outcome("t4", {"status": "CAPTURED", "transaction_id": "txn_d"})
    assert [e["trace_id"] for e in events(caplog, "TRANSACTION_FINISHED")] == ["t2", "t3", "t4"]


def test_host_health_is_published_as_a_gauge():
    observability.publish_health([HostHealth("acquirer_x", "CARD", "UP"), HostHealth("psp_y", "UPI", "DOWN")])
    assert metric("host_up", host="acquirer_x", rail="CARD") == 1
    assert metric("host_up", host="psp_y", rail="UPI") == 0


def test_an_exhausted_cascade_is_counted_and_every_hop_is_an_event(caplog):
    trail = [{"asked": h, "host": h, "status": "PENDING", "retryable": True, "error": None,
              "error_category": None, "elapsed_ms": 1500} for h in ("a1", "a2", "a3")]
    before = metric("cascade_total", outcome="exhausted")
    with caplog.at_level(logging.WARNING, logger="synapsepay.events"):
        observability.record_cascade(trail, "t9")
    hops = [(e["from_path"], e["to_path"], e["reason"]) for e in events(caplog, "FAILOVER_TRIGGERED")]
    assert hops == [("a1", "a2", "TIMEOUT"), ("a2", "a3", "TIMEOUT")]
    assert metric("cascade_total", outcome="exhausted") == before + 1


def test_the_card_service_client_sends_the_trace_id_header():
    import httpx

    from app.application.transactions import CardRequest
    from app.infrastructure.card_service_client import HttpCardProcessor

    seen = {}

    def card_service(request):
        seen["trace"] = request.headers.get("x-trace-id")
        return httpx.Response(200, json={"status": "CAPTURED", "reversal": "NOT_NEEDED",
                                         "card_bin": "411111", "card_last4": "1111"})

    processor = HttpCardProcessor("http://card-service")
    processor.client = httpx.Client(base_url="http://card-service", transport=httpx.MockTransport(card_service))
    processor.process(CardRequest(transaction_id=uuid4(), kind="PURCHASE", amount=100, currency="INR",
                                  acquirer_terminal_id="T1", acquirer_merchant_id="M1", encrypted_card_data="x",
                                  card_expiry="08/28", pin_block=None, trace_id=SDK_TRACE_HEX))
    assert seen["trace"] == SDK_TRACE_HEX


def test_recovery_stats_count_what_failover_saved_for_this_merchant_only(routed_client, ready, merchant, cards, db):
    key = routed_client.app.state.api_keys.create(merchant)
    stats = lambda k=key: routed_client.get("/api/v1/merchants/me/recovery-stats",  # noqa: E731
                                            headers={"Authorization": f"Bearer {k}"})
    assert stats().json()["cascaded"] == 0

    assert pay(routed_client, ready, merchant).status_code == 201  # psp_1 soft-declines, psp_2 approves

    body = stats().json()
    assert (body["cascaded"], body["recovered"]) == (1, 1)
    assert body["recovered_amount"] == [{"currency": "INR", "amount": 50_000}]

    (other,) = db.execute("INSERT INTO merchants DEFAULT VALUES RETURNING merchant_id").fetchone()
    assert stats(routed_client.app.state.api_keys.create(other)).json()["cascaded"] == 0, "merchant-scoped"
    assert stats("sk_test_nope").status_code == 401
    assert routed_client.get("/api/v1/merchants/me/recovery-stats?days=91",
                             headers={"Authorization": f"Bearer {key}"}).status_code == 400
