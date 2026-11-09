"""PR 10: the metrics and traces operators rely on. Centrepiece: the chaos test. Someone with database admin rights
switches off the ledger's protection and edits a posting; the gauges, the alert and the pager all notice."""
import os
import subprocess
import sys
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY, CollectorRegistry
from psycopg_pool import ConnectionPool

from app.api import errors
from app.application.fees import ConfigFeePolicy
from app.application.methods import MethodResult
from app.domain.ledger import LedgerImbalance
from app.infrastructure.db_metrics import DatabaseMetrics
from app.infrastructure.postgres_transactions import PostgresTransactionRepository


def _key_file(directory, pem: str) -> Path:
    path = directory / "jwt-public.pem"
    path.write_text(pem)
    return path


class Alerts:
    def __init__(self):
        self.raised = []

    def ops_alert(self, summary, severity, details):
        self.raised.append((severity, summary, details))


@pytest.fixture
def pool(database_url):
    with ConnectionPool(database_url, min_size=1, max_size=2) as connections:
        yield connections


def _read(pool, alerts=None) -> dict:
    """Every sample the database collector exports, by (name, labels)."""
    registry = CollectorRegistry()
    registry.register(DatabaseMetrics(pool, alerts, refresh=0))
    return {(s.name, tuple(sorted(s.labels.items()))): s.value for m in registry.collect() for s in m.samples}


def _sale(db, pool, status="CAPTURED"):
    merchant_id, terminal_id, transaction_id = uuid4(), uuid4(), uuid4()
    db.execute("INSERT INTO merchants (merchant_id) VALUES (%s)", (merchant_id,))
    db.execute("INSERT INTO terminals (terminal_id, merchant_id, device_serial, device_model) VALUES (%s, %s, %s, %s)",
               (terminal_id, merchant_id, f"SN-{transaction_id.hex[:8]}", "PAX A920 Pro"))
    db.execute("INSERT INTO transactions (transaction_id, idempotency_key, merchant_id, terminal_id, amount, currency,"
               " payment_method, capture_mode, status) VALUES (%s, %s, %s, %s, 100000, 'INR', 'CARD', 'AUTO', 'PENDING')",
               (transaction_id, uuid4(), merchant_id, terminal_id))
    if status != "PENDING":
        PostgresTransactionRepository(pool, ConfigFeePolicy({"CARD": 200})).finish(
            transaction_id, terminal_id, MethodResult(status=status, method_reference="RRN1"), status, None,
            store_response=True)
    return transaction_id


def test_a_healthy_ledger_reports_zero_everywhere(db, pool):
    _sale(db, pool)
    metrics = _read(pool)
    assert metrics[("synapse_ledger_imbalance_paise", ())] == 0
    assert metrics[("synapse_ledger_unbalanced_entries", ())] == 0
    assert all(v == 0 for (name, _), v in metrics.items() if name == "synapse_ledger_protection_disabled")
    assert metrics[("synapse_ledger_posted_paise_total", (("currency", "INR"), ("entry_type", "SALE")))] == 100_000


def test_chaos_a_dba_disables_the_protection_and_edits_a_posting(db, pool):
    """The PR 10 chaos test, as the database allows it: the append-only trigger refuses the edit, so the attacker
    first turns it off. Both steps are caught."""
    transaction_id = _sale(db, pool)
    with pytest.raises(Exception, match="append-only"):
        db.execute("UPDATE ledger_postings SET debit_amount = debit_amount + 1")  # the protection works
    alerts = Alerts()
    try:
        db.execute("ALTER TABLE ledger_postings DISABLE TRIGGER ledger_postings_append_only")
        disabled = _read(pool)
        assert disabled[("synapse_ledger_protection_disabled", (("trigger", "ledger_postings_append_only"),))] == 1
        db.execute("UPDATE ledger_postings SET debit_amount = debit_amount + 1 WHERE posting_id = (SELECT posting_id"
                   " FROM ledger_postings p JOIN journal_entries e USING (journal_entry_id) WHERE e.transaction_id = %s"
                   " AND p.debit_amount > 0 LIMIT 1)", (transaction_id,))
        tampered = _read(pool, alerts)
        assert tampered[("synapse_ledger_imbalance_paise", ())] == 1
        assert tampered[("synapse_ledger_unbalanced_entries", ())] == 1
        assert alerts.raised and alerts.raised[0][0] == "critical", "the pager is told, not just a dashboard"
        assert alerts.raised[0][2]["triggers_missing"] == ["ledger_postings_append_only"]
    finally:  # leave the shared test database as other tests expect it
        db.execute("UPDATE ledger_postings SET debit_amount = debit_amount - 1 WHERE posting_id IN (SELECT posting_id"
                   " FROM ledger_postings p JOIN journal_entries e USING (journal_entry_id) WHERE e.transaction_id = %s"
                   " AND p.debit_amount > 100000)", (transaction_id,))
        db.execute("ALTER TABLE ledger_postings ENABLE TRIGGER ledger_postings_append_only")
    assert _read(pool)[("synapse_ledger_imbalance_paise", ())] == 0


def test_stuck_payments_disputes_and_edges_are_counted(db, pool):
    stuck = _sale(db, pool, status="PENDING")
    db.execute("UPDATE transactions SET status = 'PENDING', updated_at = now() - interval '10 minutes'"
               " WHERE transaction_id = %s", (stuck,))
    _sale(db, pool, status="PENDING")  # pending for seconds: not stuck yet
    metrics = _read(pool)
    assert metrics[("synapse_stuck_transactions_current", (("kind", "pending"),))] == 1


def test_a_refused_ledger_write_is_counted_paged_and_answered_without_detail():
    app = FastAPI()
    errors.install(app)
    alerts = Alerts()
    app.state.ops_alerts = alerts

    @app.get("/boom")
    def boom():
        raise LedgerImbalance("debits 100 != credits 99 (2 postings)")

    before = REGISTRY.get_sample_value("synapse_ledger_imbalance_total", {"reason": "imbalance"}) or 0
    r = TestClient(app, raise_server_exceptions=False).get("/boom")
    assert r.status_code == 500 and "99" not in r.text
    assert REGISTRY.get_sample_value("synapse_ledger_imbalance_total", {"reason": "imbalance"}) == before + 1
    assert alerts.raised[0][0] == "critical"


def test_request_latency_is_labelled_by_route_template(client):
    client.get(f"/api/v1/terminals/{uuid4()}/authorization")  # 401, but timed
    route = "/api/v1/terminals/{terminal_id}/authorization"
    assert REGISTRY.get_sample_value("http_request_duration_seconds_count",
                                     {"method": "GET", "route": route, "status": "401"}) >= 1


def test_tracing_exports_request_and_sql_spans_with_our_trace_id(settings, database_url, tmp_path):
    """In a subprocess, because instrumentation is process-wide: a real OTLP/HTTP export, caught by a local server."""
    received = []

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Collector)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    script = textwrap.dedent(f"""
        import os, sys
        sys.path.insert(0, {str(Path(__file__).parents[1])!r})
        from dataclasses import replace
        from fastapi.testclient import TestClient
        from opentelemetry import trace
        from app.config import Settings
        from app.main import create_app
        settings = Settings.from_env()
        with TestClient(create_app(settings)) as client:
            client.get("/api/v1/terminals/00000000-0000-0000-0000-000000000001",
                       headers={{"X-Trace-Id": "4bf92f3577b34da6a3ce929d0e0e4736"}})
        trace.get_tracer_provider().force_flush()
    """)
    env = {**os.environ, "OTEL_EXPORTER_OTLP_ENDPOINT": f"http://127.0.0.1:{server.server_port}",
           "DATABASE_URL": database_url, "CA_CERT_PATH": str(settings.ca_cert_path),
           "CA_KEY_PATH": str(settings.ca_key_path), "CA_CRL_PATH": str(settings.ca_crl_path),
           "JWT_PUBLIC_KEY_PATH": str(_key_file(tmp_path, settings.jwt_public_key)), "HEALTH_POLL_SECONDS": "3600"}
    done = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=120)
    server.shutdown()
    assert done.returncode == 0, done.stderr[-2000:]
    payload = b"".join(received)
    assert b"synapsepay.trace_id" in payload and b"4bf92f3577b34da6a3ce929d0e0e4736" in payload
    assert b"SELECT" in payload, "the certification matrix load, at least, is a traced SQL statement"
