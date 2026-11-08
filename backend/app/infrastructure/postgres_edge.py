"""Edge nodes in Postgres (Step 20). Every admin change is audited in the same transaction, like the registry."""
from uuid import UUID

from psycopg import errors
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.application.edge import EdgeNode, OfflineLimits
from app.application.registration import IssuedCertificate, NotFound, UnknownReference
from app.infrastructure.postgres_terminals import _OUTBOX_LOCK

_COLUMNS = ("edge_node_id, merchant_id, status, rules_version, offline_per_transaction, offline_per_day,"
            " offline_max_age_minutes")


def _audit(conn, actor_id: str, edge_node_id: UUID, action: str, payload: dict) -> None:
    conn.execute("SELECT pg_advisory_xact_lock_shared(%s)", (_OUTBOX_LOCK,))  # same rule as every audit writer
    conn.execute(
        "INSERT INTO audit_log (actor_type, actor_id, entity_type, entity_id, action, from_status, to_status,"
        " payload) VALUES ('ADMIN', %s, 'edge_node', %s, %s, 'ACTIVE', 'ACTIVE', %s)",
        (actor_id, edge_node_id, action, Jsonb(payload)))


class PostgresEdgeNodes:
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def create(self, edge_node_id: UUID, merchant_id: UUID, limits: OfflineLimits, cert: IssuedCertificate,
               actor_id: str) -> None:
        with self.pool.connection() as conn, conn.transaction():
            try:
                conn.execute(
                    "INSERT INTO edge_nodes (edge_node_id, merchant_id, certificate_serial, public_key_pem,"
                    " offline_per_transaction, offline_per_day, offline_max_age_minutes)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (edge_node_id, merchant_id, cert.serial_number, cert.public_key_pem, limits.per_transaction,
                     limits.per_day, limits.max_age_minutes))
            except errors.ForeignKeyViolation:
                raise UnknownReference("merchant not found", code="MERCHANT_NOT_FOUND")
            _audit(conn, actor_id, edge_node_id, "edge.register",
                   {"merchant_id": str(merchant_id), "certificate_serial": cert.serial_number,
                    "offline_limits": limits.__dict__})

    def get(self, edge_node_id: UUID) -> EdgeNode | None:
        with self.pool.connection() as conn:
            row = conn.execute(f"SELECT {_COLUMNS} FROM edge_nodes WHERE edge_node_id = %s",
                               (edge_node_id,)).fetchone()
        return _node(row) if row else None

    def public_key(self, edge_node_id: UUID) -> str | None:
        """For the sync endpoint: the key that signs this edge's queued payments, if it is active."""
        with self.pool.connection() as conn:
            row = conn.execute("SELECT public_key_pem FROM edge_nodes WHERE edge_node_id = %s AND status = 'ACTIVE'",
                               (edge_node_id,)).fetchone()
        return row[0] if row else None

    def update_limits(self, edge_node_id: UUID, limits: OfflineLimits, actor_id: str) -> int:
        with self.pool.connection() as conn, conn.transaction():
            row = conn.execute(
                "UPDATE edge_nodes SET offline_per_transaction = %s, offline_per_day = %s,"
                " offline_max_age_minutes = %s, rules_version = rules_version + 1, updated_at = now()"
                " WHERE edge_node_id = %s RETURNING rules_version",
                (limits.per_transaction, limits.per_day, limits.max_age_minutes, edge_node_id)).fetchone()
            if row is None:
                raise NotFound("edge node not found")
            _audit(conn, actor_id, edge_node_id, "edge.update_limits",
                   {"rules_version": row[0], "offline_limits": limits.__dict__})
            return row[0]

    def active_terminals(self, merchant_id: UUID) -> list[str]:
        with self.pool.connection() as conn:
            rows = conn.execute("SELECT terminal_id FROM terminals WHERE merchant_id = %s AND status = 'ACTIVE'",
                                (merchant_id,)).fetchall()
        return [str(r[0]) for r in rows]


def _node(row) -> EdgeNode:
    edge_node_id, merchant_id, status, version, per_txn, per_day, max_age = row
    return EdgeNode(edge_node_id, merchant_id, status, version, OfflineLimits(per_txn, per_day, max_age))
