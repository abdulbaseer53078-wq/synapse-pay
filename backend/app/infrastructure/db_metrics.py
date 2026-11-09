"""Metrics read from the database (PR 10): the financial invariants, stuck payments, disputes and the edge network.

They come from the database, not from counters in memory, so every API instance reports the same truth (dashboards
take max() across instances) and a restart loses nothing. Read at most every REFRESH_SECONDS, whatever the scrape rate.

The ledger checks matter most. The database already refuses an unbalanced entry and any edit to a posting; what's left
is someone with database admin rights switching those triggers off and editing rows. So every refresh checks that the
triggers are still on, that the whole ledger still balances, and that recent entries each balance.
"""
import threading
import time

from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from prometheus_client.registry import Collector
from psycopg_pool import ConnectionPool

REFRESH_SECONDS = 30
LEDGER_TRIGGERS = ("journal_entries_append_only", "ledger_postings_append_only", "journal_entries_balance",
                   "ledger_postings_balance")
# shortcut: per-entry balance is checked over the last day's entries; the global sum covers all of them. Track a
# watermark instead once the ledger is large enough for the daily window to be slow.
RECENT_ENTRIES = "1 day"


def ledger_health(conn) -> dict:
    """The ledger's integrity, for the gauges and for the chaos test that proves they catch tampering."""
    (total_debit, total_credit) = conn.execute(
        "SELECT coalesce(sum(debit_amount), 0), coalesce(sum(credit_amount), 0) FROM ledger_postings").fetchone()
    (unbalanced,) = conn.execute(
        f"SELECT count(*) FROM (SELECT e.journal_entry_id FROM journal_entries e"
        f" LEFT JOIN ledger_postings p USING (journal_entry_id) WHERE e.created_at > now() - interval '{RECENT_ENTRIES}'"
        f" GROUP BY e.journal_entry_id HAVING coalesce(sum(p.debit_amount), 0) <> coalesce(sum(p.credit_amount), 0)"
        f" OR count(p.posting_id) < 2) bad").fetchone()
    enabled = {name for (name,) in conn.execute(
        "SELECT tgname FROM pg_trigger WHERE tgname = ANY(%s) AND tgenabled <> 'D'", (list(LEDGER_TRIGGERS),))}
    return {"imbalance": int(total_debit) - int(total_credit), "unbalanced_entries": int(unbalanced),
            "triggers_missing": sorted(set(LEDGER_TRIGGERS) - enabled)}


class DatabaseMetrics(Collector):
    def __init__(self, pool: ConnectionPool, alerts=None, refresh: float = REFRESH_SECONDS):
        self.pool = pool
        self.alerts = alerts
        self.refresh = refresh
        self._lock = threading.Lock()
        self._at = 0.0
        self._cached: list = []
        self._alerted = False

    def collect(self):
        with self._lock:
            if time.monotonic() - self._at >= self.refresh:
                try:
                    self._cached = self._read()
                except Exception as exc:  # noqa: BLE001  a scrape must not crash; the up/absent alerts cover it
                    print(f"database metrics unavailable: {type(exc).__name__}")
                self._at = time.monotonic()
            yield from self._cached

    def _read(self) -> list:
        with self.pool.connection() as conn:
            health = ledger_health(conn)
            volume = conn.execute(
                "SELECT e.entry_type, e.currency, coalesce(sum(p.debit_amount), 0) FROM journal_entries e"
                " JOIN ledger_postings p USING (journal_entry_id) GROUP BY 1, 2").fetchall()
            (stuck_pending,) = conn.execute(
                "SELECT count(*) FROM transactions WHERE status = 'PENDING' AND updated_at < now() - interval '5 minutes'"
            ).fetchone()
            (stuck_in_flight,) = conn.execute(
                "SELECT count(*) FROM idempotency_keys WHERE state = 'IN_FLIGHT' AND created_at < now() - interval '5 minutes'"
            ).fetchone()
            chargebacks = conn.execute("SELECT status, count(*) FROM chargebacks GROUP BY 1").fetchall()
            edges = conn.execute(
                "SELECT n.edge_node_id::text, n.flagged_at IS NOT NULL, extract(epoch FROM now() - max(i.received_at))"
                " FROM edge_nodes n LEFT JOIN edge_sync_items i USING (edge_node_id) WHERE n.status = 'ACTIVE'"
                " GROUP BY n.edge_node_id, n.flagged_at").fetchall()
            offline = conn.execute(
                "SELECT CASE WHEN status = 'FAILED' THEN 'declined' ELSE 'accepted' END, count(*) FROM transactions"
                " WHERE metadata ? 'offline_local_timestamp' GROUP BY 1").fetchall()

        if (health["imbalance"] or health["unbalanced_entries"] or health["triggers_missing"]) and not self._alerted:
            self._alerted = True  # once per process; the Prometheus alert keeps firing for as long as it lasts
            if self.alerts:
                self.alerts.ops_alert("CRITICAL: the ledger no longer balances or its protections are off", "critical",
                                      health)

        imbalance = GaugeMetricFamily("synapse_ledger_imbalance_paise",
                                      "All debits minus all credits in the ledger: must be exactly 0")
        imbalance.add_metric([], health["imbalance"])
        unbalanced = GaugeMetricFamily("synapse_ledger_unbalanced_entries",
                                       f"Journal entries from the last {RECENT_ENTRIES} that don't balance: must be 0")
        unbalanced.add_metric([], health["unbalanced_entries"])
        triggers = GaugeMetricFamily("synapse_ledger_protection_disabled",
                                     "1 for each ledger trigger (append-only, balance) that is missing or disabled",
                                     labels=["trigger"])
        for name in LEDGER_TRIGGERS:
            triggers.add_metric([name], 1 if name in health["triggers_missing"] else 0)
        value = CounterMetricFamily("synapse_ledger_posted_paise", "Money posted to the ledger, by entry type",
                                    labels=["entry_type", "currency"])
        for entry_type, currency, amount in volume:
            value.add_metric([entry_type, currency], int(amount))
        stuck = GaugeMetricFamily("synapse_stuck_transactions_current",
                                  "Payments stuck for over 5 minutes: PENDING, or claimed and never finished",
                                  labels=["kind"])
        stuck.add_metric(["pending"], stuck_pending)
        stuck.add_metric(["in_flight"], stuck_in_flight)
        disputes = CounterMetricFamily("synapse_chargebacks", "Chargebacks received, by current status",
                                       labels=["status"])
        for status, count in chargebacks:
            disputes.add_metric([status], count)
        edge_age = GaugeMetricFamily("synapse_edge_last_sync_age_seconds",
                                     "Seconds since an edge last synced a sale (NaN: never)", labels=["edge_node_id"])
        edge_hold = GaugeMetricFamily("synapse_edge_on_hold", "1 if the edge's offline sales are on hold for review",
                                      labels=["edge_node_id"])
        for edge_id, flagged, age in edges:
            edge_age.add_metric([edge_id], float(age) if age is not None else float("nan"))
            edge_hold.add_metric([edge_id], 1 if flagged else 0)
        synced = CounterMetricFamily("synapse_offline_sales", "Offline sales synced, accepted or declined at sync",
                                     labels=["outcome"])
        for outcome, count in offline:
            synced.add_metric([outcome], count)
        return [imbalance, unbalanced, triggers, value, stuck, disputes, edge_age, edge_hold, synced]
