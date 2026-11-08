"""Certification test harness runs in Postgres (Step 27). Recording one is an admin action, so it is audited."""
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.application.certification import CertificationRun
from app.infrastructure.postgres_certification import _audit

_COLUMNS = "run_id, device_model, firmware_version, driver, passed, schemes, report, recorded_at"


def _run(row) -> CertificationRun:
    return CertificationRun(*row[:5], frozenset(row[5]), *row[6:])


class PostgresCertificationRuns:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def record(self, run: CertificationRun, actor_id: str) -> CertificationRun:
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute(
                "INSERT INTO certification_runs (run_id, device_model, firmware_version, driver, passed, schemes,"
                f" report, recorded_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING {_COLUMNS}",
                (run.run_id, run.device_model, run.firmware_version, run.driver, run.passed, sorted(run.schemes),
                 Jsonb(run.report), actor_id)).fetchone()
            _audit(conn, actor_id, "certification_run", run.run_id, "certification_run.record", None,
                   "PASSED" if run.passed else "FAILED",
                   {"device_model": run.device_model, "firmware_version": run.firmware_version,
                    "driver": run.driver, "schemes": sorted(run.schemes)})
        return _run(row)

    def latest(self, device_model: str, firmware_version: str) -> CertificationRun | None:
        with self.pool.connection() as conn:
            row = conn.execute(
                f"SELECT {_COLUMNS} FROM certification_runs WHERE device_model = %s AND firmware_version = %s"
                " ORDER BY recorded_at DESC, run_id LIMIT 1", (device_model, firmware_version)).fetchone()
        return row and _run(row)
