from collections.abc import Callable, Collection
from datetime import datetime, timedelta
from uuid import UUID

from psycopg import Connection, errors
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.application.registration import (ActivationState, Conflict, Heartbeat, HeartbeatContext,
                                          IssuedCertificate, NotFound, TerminalSnapshot, Unauthenticated,
                                          UnknownReference)
from app.application.authorization import AuthorizationContext
from app.application.events import AuditRecord
from app.application.queries import CertificateView, HeartbeatView, StatusEvent, TerminalView
from app.domain.terminal import (DEGRADED_WITHIN, HEALTHY_WITHIN, Actor, CertificationProfile, HealthState,
                                 TerminalStatus)

# In TerminalView field order.
_TERMINAL_COLUMNS = ("terminal_id, merchant_id, device_serial, device_model, firmware_version, status, health_state,"
                     " last_heartbeat_at, certification_profile_id, registered_at, activated_at, status_changed_at,"
                     " metadata")


# Audit writers hold this shared until commit; the event relay takes it exclusively before reading, so it only
# ever sees committed rows and no row can commit later with an audit_id below the relay's cursor.
_OUTBOX_LOCK = 7_340_001


def _audit(conn: Connection, actor: Actor, actor_id: str | None, terminal_id: UUID, action: str,
           from_status: str | None, to_status: str, reason: str | None = None) -> None:
    conn.execute("SELECT pg_advisory_xact_lock_shared(%s)", (_OUTBOX_LOCK,))
    conn.execute(
        "INSERT INTO audit_log (actor_type, actor_id, entity_type, entity_id, action, from_status, to_status, reason)"
        " VALUES (%s, %s, 'terminal', %s, %s, %s, %s, %s)",
        (actor, actor_id, terminal_id, action, from_status, to_status, reason))


class PostgresTerminalRepository:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def create_terminal(self, merchant_id: UUID, device_serial: str, device_model: str, metadata: dict,
                        token_hash: bytes, token_ttl: timedelta) -> tuple[UUID, datetime]:
        with self.pool.connection() as conn:
            try:
                (terminal_id,) = conn.execute(
                    "INSERT INTO terminals (merchant_id, device_serial, device_model, metadata)"
                    " VALUES (%s, %s, %s, %s) RETURNING terminal_id",
                    (merchant_id, device_serial, device_model, Jsonb(metadata))).fetchone()
            except errors.UniqueViolation:
                raise Conflict("device_serial is already registered")
            except errors.ForeignKeyViolation:
                raise UnknownReference("merchant not found", code="MERCHANT_NOT_FOUND")
            (expires_at,) = conn.execute(
                "INSERT INTO registration_tokens (token_hash, terminal_id, expires_at)"
                " VALUES (%s, %s, now() + %s) RETURNING expires_at",
                (token_hash, terminal_id, token_ttl)).fetchone()
            _audit(conn, Actor.MERCHANT, str(merchant_id), terminal_id, "create", None, TerminalStatus.PENDING)
            return terminal_id, expires_at

    def pending_model(self, terminal_id: UUID, token_hash: bytes) -> str | None:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT t.device_model FROM registration_tokens r JOIN terminals t USING (terminal_id)"
                " WHERE r.terminal_id = %s AND r.token_hash = %s AND r.used_at IS NULL"
                " AND r.expires_at > now() AND t.status = 'PENDING'",
                (terminal_id, token_hash)).fetchone()
            return row[0] if row else None

    @staticmethod
    def _consume_token(conn: Connection, terminal_id: UUID, token_hash: bytes) -> bool:
        # The row lock taken here makes a concurrent request with the same token wait, then find it used.
        return conn.execute(
            "UPDATE registration_tokens SET used_at = now()"
            " WHERE terminal_id = %s AND token_hash = %s AND used_at IS NULL AND expires_at > now()"
            " RETURNING 1", (terminal_id, token_hash)).fetchone() is not None

    def complete_registration(self, terminal_id: UUID, token_hash: bytes, cert: IssuedCertificate,
                              secure_element_id: str, firmware_version: str,
                              challenge: bytes, challenge_ttl: timedelta) -> datetime | None:
        with self.pool.connection() as conn:
            if not self._consume_token(conn, terminal_id, token_hash):
                return None
            (certificate_id,) = conn.execute(
                "INSERT INTO certificates (terminal_id, serial_number, public_key_pem, issued_at, expires_at)"
                " VALUES (%s, %s, %s, %s, %s) RETURNING certificate_id",
                (terminal_id, cert.serial_number, cert.public_key_pem, cert.issued_at, cert.expires_at)).fetchone()
            updated = conn.execute(
                "UPDATE terminals SET status = 'PENDING_ACTIVATION', certificate_id = %s,"
                " secure_element_id = %s, firmware_version = %s, status_changed_at = now()"
                " WHERE terminal_id = %s AND status = 'PENDING'",
                (certificate_id, secure_element_id, firmware_version, terminal_id))
            if updated.rowcount != 1:
                conn.rollback()
                return None
            (expires_at,) = conn.execute(
                "INSERT INTO activation_challenges (terminal_id, challenge, expires_at)"
                " VALUES (%s, %s, now() + %s) RETURNING expires_at",
                (terminal_id, challenge, challenge_ttl)).fetchone()
            _audit(conn, Actor.TERMINAL, str(terminal_id), terminal_id, "register",
                   TerminalStatus.PENDING, TerminalStatus.PENDING_ACTIVATION)
            return expires_at

    def reject(self, terminal_id: UUID, token_hash: bytes, reason: str) -> None:
        with self.pool.connection() as conn:
            if not self._consume_token(conn, terminal_id, token_hash):
                return
            updated = conn.execute(
                "UPDATE terminals SET status = 'REJECTED', status_changed_at = now()"
                " WHERE terminal_id = %s AND status = 'PENDING'", (terminal_id,))
            if updated.rowcount == 1:
                _audit(conn, Actor.SYSTEM, None, terminal_id, "reject",
                       TerminalStatus.PENDING, TerminalStatus.REJECTED, reason)

    def activation_state(self, terminal_id: UUID) -> ActivationState | None:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT t.status, c.public_key_pem, a.challenge, coalesce(a.expires_at > now(), false)"
                " FROM terminals t"
                " LEFT JOIN certificates c ON c.certificate_id = t.certificate_id"
                " LEFT JOIN activation_challenges a ON a.terminal_id = t.terminal_id"
                " WHERE t.terminal_id = %s", (terminal_id,)).fetchone()
            return ActivationState(TerminalStatus(row[0]), row[1], row[2], row[3]) if row else None

    def activate(self, terminal_id: UUID) -> datetime | None:
        with self.pool.connection() as conn:
            row = conn.execute(
                "UPDATE terminals SET status = 'ACTIVE', activated_at = now(), status_changed_at = now()"
                " WHERE terminal_id = %s AND status = 'PENDING_ACTIVATION' RETURNING activated_at",
                (terminal_id,)).fetchone()
            if row is None:
                return None
            conn.execute("DELETE FROM activation_challenges WHERE terminal_id = %s", (terminal_id,))
            _audit(conn, Actor.TERMINAL, str(terminal_id), terminal_id, "activate",
                   TerminalStatus.PENDING_ACTIVATION, TerminalStatus.ACTIVE)
            return row[0]

    def transition(self, terminal_id: UUID, to: TerminalStatus, check: Callable[[TerminalSnapshot], None],
                   actor: Actor, actor_id: str, action: str, reason: str | None,
                   revoke_certificate: bool) -> datetime:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT t.merchant_id, t.status, c.serial_number FROM terminals t"
                " LEFT JOIN certificates c ON c.certificate_id = t.certificate_id"
                " WHERE t.terminal_id = %s FOR UPDATE OF t", (terminal_id,)).fetchone()
            if row is None:
                raise NotFound("terminal not found")
            current = TerminalSnapshot(row[0], TerminalStatus(row[1]), row[2])
            check(current)  # raising here leaves the connection context, which rolls back
            (changed_at,) = conn.execute(
                "UPDATE terminals SET status = %s, status_changed_at = now() WHERE terminal_id = %s"
                " RETURNING status_changed_at", (to, terminal_id)).fetchone()
            if revoke_certificate:
                conn.execute(
                    "UPDATE certificates SET revoked_at = now(), revocation_reason = %s"
                    " WHERE certificate_id = (SELECT certificate_id FROM terminals WHERE terminal_id = %s)"
                    " AND revoked_at IS NULL", (reason or action, terminal_id))
            _audit(conn, actor, actor_id, terminal_id, action, current.status, to, reason)
            return changed_at

    def heartbeat_context(self, terminal_id: UUID) -> HeartbeatContext | None:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT t.status, t.device_model, t.firmware_version, c.public_key_pem FROM terminals t"
                " LEFT JOIN certificates c ON c.certificate_id = t.certificate_id"
                " WHERE t.terminal_id = %s", (terminal_id,)).fetchone()
            return HeartbeatContext(TerminalStatus(row[0]), row[1], row[2], row[3]) if row else None

    def record_heartbeat(self, terminal_id: UUID, hb: Heartbeat, update_terminal: bool,
                         suspend_reason: str | None) -> tuple[TerminalStatus, HealthState]:
        with self.pool.connection() as conn:
            # Lock the terminal so concurrent heartbeats are ordered for the replay check below.
            status, health, firmware = conn.execute(
                "SELECT status, health_state, firmware_version FROM terminals WHERE terminal_id = %s FOR UPDATE",
                (terminal_id,)).fetchone()
            # Accepted heartbeats are strictly ordered, so the latest received has the largest sent_at;
            # this reads one row via heartbeats_terminal_received_idx instead of scanning the history.
            previous = conn.execute("SELECT sent_at FROM heartbeats WHERE terminal_id = %s"
                                    " ORDER BY received_at DESC LIMIT 1", (terminal_id,)).fetchone()
            if previous is not None and hb.sent_at <= previous[0]:
                raise Unauthenticated("heartbeat replayed: sent_at is not later than the previous heartbeat")
            conn.execute(
                "INSERT INTO heartbeats (terminal_id, sent_at, signature_valid, connectivity_type, latency_ms,"
                " firmware_version, battery_level) VALUES (%s, %s, true, %s, %s, %s, %s)",
                (terminal_id, hb.sent_at, hb.connectivity_type, hb.latency_ms, hb.firmware_version,
                 hb.battery_level))
            if update_terminal:
                conn.execute(
                    "UPDATE terminals SET last_heartbeat_at = now(), firmware_version = %s, health_state = 'HEALTHY'"
                    " WHERE terminal_id = %s", (hb.firmware_version, terminal_id))
                if health != HealthState.HEALTHY:  # it just checked in
                    _audit(conn, Actor.SYSTEM, None, terminal_id, "health_change", health, HealthState.HEALTHY)
                    health = HealthState.HEALTHY
                if hb.firmware_version != firmware:
                    _audit(conn, Actor.TERMINAL, str(terminal_id), terminal_id, "firmware_change", firmware,
                           hb.firmware_version)
            if suspend_reason and status == TerminalStatus.ACTIVE:
                conn.execute("UPDATE terminals SET status = 'SUSPENDED', status_changed_at = now()"
                             " WHERE terminal_id = %s", (terminal_id,))
                _audit(conn, Actor.SYSTEM, None, terminal_id, "suspend", status, TerminalStatus.SUSPENDED,
                       suspend_reason)
                status = TerminalStatus.SUSPENDED
            return TerminalStatus(status), HealthState(health)

    def authorization_context(self, terminal_id: UUID) -> AuthorizationContext | None:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT t.status, t.status_changed_at, t.last_heartbeat_at, t.device_model, t.firmware_version,"
                " p.profile_id, p.certified_for, p.expires_at, p.per_transaction_limit, p.per_day_limit"
                " FROM terminals t"
                " LEFT JOIN certification_profiles p ON p.profile_id = t.certification_profile_id"
                " WHERE t.terminal_id = %s", (terminal_id,)).fetchone()
            if row is None:
                return None
            profile = CertificationProfile(row[5], frozenset(row[6]), *row[7:]) if row[5] else None
            return AuthorizationContext(TerminalStatus(row[0]), *row[1:5], profile)

    def terminal(self, terminal_id: UUID, merchant_id: UUID | None) -> TerminalView | None:
        with self.pool.connection() as conn:
            row = conn.execute(f"SELECT {_TERMINAL_COLUMNS} FROM terminals WHERE terminal_id = %(id)s"
                               " AND (%(m)s::uuid IS NULL OR merchant_id = %(m)s)",
                               {"id": terminal_id, "m": merchant_id}).fetchone()
            return TerminalView(*row) if row else None

    def list_terminals(self, merchant_id: UUID, status: str | None, health: str | None, after: UUID | None,
                       limit: int) -> list[TerminalView]:
        with self.pool.connection() as conn:
            # Keyset pagination on terminals_merchant_id_idx (merchant_id, terminal_id).
            rows = conn.execute(
                f"SELECT {_TERMINAL_COLUMNS} FROM terminals WHERE merchant_id = %(m)s"
                " AND (%(status)s::terminal_status IS NULL OR status = %(status)s::terminal_status)"
                " AND (%(health)s::terminal_health IS NULL OR health_state = %(health)s::terminal_health)"
                " AND (%(after)s::uuid IS NULL OR terminal_id > %(after)s)"
                " ORDER BY terminal_id LIMIT %(limit)s",
                {"m": merchant_id, "status": status, "health": health, "after": after, "limit": limit}).fetchall()
            return [TerminalView(*r) for r in rows]

    def update_metadata(self, terminal_id: UUID, merchant_id: UUID | None, metadata: dict) -> TerminalView | None:
        with self.pool.connection() as conn:
            row = conn.execute(f"UPDATE terminals SET metadata = %(md)s WHERE terminal_id = %(id)s"
                               f" AND (%(m)s::uuid IS NULL OR merchant_id = %(m)s) RETURNING {_TERMINAL_COLUMNS}",
                               {"md": Jsonb(metadata), "id": terminal_id, "m": merchant_id}).fetchone()
            return TerminalView(*row) if row else None

    def certificates(self, terminal_id: UUID) -> list[CertificateView]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT c.serial_number, c.issued_at, c.expires_at, c.revoked_at, c.revocation_reason,"
                " coalesce(c.certificate_id = t.certificate_id, false)"
                " FROM certificates c JOIN terminals t USING (terminal_id)"
                " WHERE c.terminal_id = %s ORDER BY c.issued_at DESC", (terminal_id,)).fetchall()
            return [CertificateView(*r) for r in rows]

    def heartbeats(self, terminal_id: UUID, limit: int) -> list[HeartbeatView]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT sent_at, received_at, connectivity_type, latency_ms, firmware_version, battery_level"
                " FROM heartbeats WHERE terminal_id = %s ORDER BY received_at DESC LIMIT %s",
                (terminal_id, limit)).fetchall()
            return [HeartbeatView(*r) for r in rows]

    def status_events(self, terminal_id: UUID) -> list[StatusEvent]:
        with self.pool.connection() as conn:
            # Status changes only: admin-access rows have no to_status; firmware and health rows aren't statuses.
            rows = conn.execute(
                "SELECT occurred_at, action, from_status, to_status, actor_type, reason FROM audit_log"
                " WHERE entity_type = 'terminal' AND entity_id = %s AND to_status IS NOT NULL"
                " AND action NOT IN ('firmware_change', 'health_change')"
                " ORDER BY audit_id", (terminal_id,)).fetchall()
            return [StatusEvent(*r) for r in rows]

    def audit_access(self, admin_id: str, entity_type: str, entity_id: UUID, action: str) -> None:
        with self.pool.connection() as conn:
            conn.execute("INSERT INTO audit_log (actor_type, actor_id, entity_type, entity_id, action)"
                         " VALUES ('ADMIN', %s, %s, %s, %s)", (admin_id, entity_type, entity_id, action))

    def refresh_health(self) -> int:
        computed = ("CASE WHEN last_heartbeat_at > now() - %(healthy)s THEN 'HEALTHY'"
                    " WHEN last_heartbeat_at > now() - %(degraded)s THEN 'DEGRADED'"
                    " ELSE 'UNREACHABLE' END::terminal_health")
        with self.pool.connection() as conn:
            conn.execute("SELECT pg_advisory_xact_lock_shared(%s)", (_OUTBOX_LOCK,))
            # SKIP LOCKED: a terminal mid-heartbeat is left for the next run rather than overwritten with
            # health computed from its previous heartbeat. Each change is audited (and so emitted).
            return conn.execute(
                f"WITH due AS (SELECT terminal_id, health_state AS from_health, {computed} AS to_health FROM terminals"
                f"             WHERE health_state <> {computed} FOR UPDATE SKIP LOCKED),"
                " changed AS (UPDATE terminals t SET health_state = due.to_health FROM due"
                "             WHERE t.terminal_id = due.terminal_id RETURNING t.terminal_id, due.from_health, due.to_health)"
                " INSERT INTO audit_log (actor_type, entity_type, entity_id, action, from_status, to_status)"
                " SELECT 'SYSTEM', 'terminal', terminal_id, 'health_change', from_health, to_health FROM changed",
                {"healthy": HEALTHY_WITHIN, "degraded": DEGRADED_WITHIN}).rowcount

    def relay(self, actions: Collection[str], publish: Callable[[list[AuditRecord]], None], limit: int) -> int:
        with self.pool.connection() as conn:
            # The cursor row lock keeps a second relay out until this batch is published and committed.
            (cursor,) = conn.execute("SELECT last_audit_id FROM event_outbox_cursor FOR UPDATE").fetchone()
            conn.execute("SELECT pg_advisory_lock(%s)", (_OUTBOX_LOCK,))  # waits out in-flight audit writers
            try:
                rows = conn.execute(
                    "SELECT a.audit_id, a.event_id, a.action, a.entity_id, t.merchant_id, a.actor_type, a.actor_id,"
                    " a.occurred_at, a.from_status, a.to_status, a.reason"
                    " FROM audit_log a JOIN terminals t ON t.terminal_id = a.entity_id"
                    " WHERE a.audit_id > %s AND a.entity_type = 'terminal' AND a.action = ANY(%s)"
                    " ORDER BY a.audit_id LIMIT %s", (cursor, list(actions), limit)).fetchall()
            finally:
                conn.execute("SELECT pg_advisory_unlock(%s)", (_OUTBOX_LOCK,))  # don't block writers on Kafka
            if not rows:
                return 0
            publish([AuditRecord(*r[1:]) for r in rows])  # raising rolls back: the cursor stays put
            conn.execute("UPDATE event_outbox_cursor SET last_audit_id = %s", (rows[-1][0],))
            return len(rows)
