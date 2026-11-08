"""The certification matrix in Postgres (Step 26). Every change is audited and announced in the same transaction:
NOTIFY is delivered only on commit, so no process reloads a change that rolled back, and none misses one that
committed while it was listening."""
import threading
import uuid
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg import errors
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.application.certification import Snapshot, snapshot
from app.application.registration import Conflict, NotFound
from app.domain.certification import Certification
from app.infrastructure.postgres_terminals import _OUTBOX_LOCK

CHANNEL = "certifications_changed"
_COLUMNS = ("certification_id, device_model, firmware_version, scheme, acquirer_id, certificate_number, status,"
            " valid_from, valid_until")


def _audit(conn, actor_id: str, entity_type: str, entity_id: UUID, action: str, from_status: str | None,
           to_status: str, payload: dict) -> None:
    conn.execute("SELECT pg_advisory_xact_lock_shared(%s)", (_OUTBOX_LOCK,))  # same rule as every audit writer
    conn.execute(
        "INSERT INTO audit_log (actor_type, actor_id, entity_type, entity_id, action, from_status, to_status,"
        " payload) VALUES ('ADMIN', %s, %s, %s, %s, %s, %s, %s)",
        (actor_id, entity_type, entity_id, action, from_status, to_status, Jsonb(payload)))
    conn.execute("SELECT pg_notify(%s, '')", (CHANNEL,))


def _model_id(device_model: str) -> UUID:
    """audit_log.entity_id is a UUID; a model has none, so it gets a stable one from its name."""
    return uuid.uuid5(uuid.NAMESPACE_URL, f"urn:synapsepay:device-model:{device_model}")


class PostgresCertifications:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def load(self) -> Snapshot:
        with self.pool.connection() as conn:
            rows = conn.execute(f"SELECT {_COLUMNS} FROM certifications").fetchall()
            minimums = conn.execute("SELECT device_model, minimum_secure_firmware FROM firmware_minimums").fetchall()
        return snapshot([Certification(*r) for r in rows], dict(minimums))

    def create(self, cert: Certification, actor_id: str) -> None:
        with self.pool.connection() as conn, conn.transaction():
            try:
                conn.execute(f"INSERT INTO certifications ({_COLUMNS}) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                             (cert.certification_id, cert.device_model, cert.firmware_version, cert.scheme,
                              cert.acquirer_id, cert.certificate_number, cert.status, cert.valid_from,
                              cert.valid_until))
            except errors.UniqueViolation:
                raise Conflict("this model, firmware, scheme and acquirer is already certified",
                               code="CERTIFICATION_EXISTS")
            _audit(conn, actor_id, "certification", cert.certification_id, "certification.create", None, cert.status,
                   _payload(cert))

    def update(self, certification_id: UUID, status: str | None, valid_until: datetime | None,
               actor_id: str) -> Certification:
        with self.pool.connection() as conn, conn.transaction():
            before = conn.execute(f"SELECT {_COLUMNS} FROM certifications WHERE certification_id = %s FOR UPDATE",
                                  (certification_id,)).fetchone()
            if before is None:
                raise NotFound("certification not found")
            row = conn.execute(
                f"UPDATE certifications SET status = coalesce(%s, status), valid_until = coalesce(%s, valid_until),"
                f" updated_at = now() WHERE certification_id = %s RETURNING {_COLUMNS}",
                (status, valid_until, certification_id)).fetchone()
            cert = Certification(*row)
            _audit(conn, actor_id, "certification", certification_id, "certification.update", before[6], cert.status,
                   _payload(cert))
            return cert

    def set_minimum(self, device_model: str, minimum: str, actor_id: str) -> None:
        with self.pool.connection() as conn, conn.transaction():
            previous = conn.execute("SELECT minimum_secure_firmware FROM firmware_minimums WHERE device_model = %s"
                                    " FOR UPDATE", (device_model,)).fetchone()
            conn.execute("INSERT INTO firmware_minimums (device_model, minimum_secure_firmware) VALUES (%s, %s)"
                         " ON CONFLICT (device_model) DO UPDATE SET minimum_secure_firmware = excluded.minimum_secure_firmware,"
                         " updated_at = now()", (device_model, minimum))
            _audit(conn, actor_id, "device_model", _model_id(device_model), "firmware.set_minimum",
                   previous[0] if previous else None, minimum, {"device_model": device_model})

    def list(self, device_model: str | None, firmware_version: str | None) -> list[Certification]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                f"SELECT {_COLUMNS} FROM certifications WHERE (%(m)s::varchar IS NULL OR device_model = %(m)s)"
                " AND (%(f)s::varchar IS NULL OR firmware_version = %(f)s)"
                " ORDER BY device_model, firmware_version, scheme, acquirer_id",
                {"m": device_model, "f": firmware_version}).fetchall()
        return [Certification(*r) for r in rows]


def _payload(cert: Certification) -> dict:
    return {"device_model": cert.device_model, "firmware_version": cert.firmware_version, "scheme": cert.scheme,
            "acquirer_id": cert.acquirer_id, "certificate_number": cert.certificate_number,
            "valid_from": cert.valid_from.isoformat(), "valid_until": cert.valid_until.isoformat()}


def listen(database_url: str, reload, stop: threading.Event) -> None:
    """Reload on every committed change, and on every (re)connect: a change made while we were disconnected
    sent its notification to nobody, so the only safe resume is a full reload."""
    while not stop.is_set():
        try:
            with psycopg.connect(database_url, autocommit=True) as conn:
                conn.execute(f"LISTEN {CHANNEL}")
                reload()
                while not stop.is_set():
                    for _ in conn.notifies(timeout=1.0, stop_after=1):
                        reload()
        except Exception as exc:  # the matrix is cleared on a failed reload, so payments fail closed meanwhile
            print(f"certification listener: {type(exc).__name__}; reconnecting")
            stop.wait(1.0)
