from typing import Callable

from psycopg_pool import ConnectionPool


def database_writable(pool: ConnectionPool, timeout: float = 2.0) -> Callable[[], bool]:
    """True if this region's database accepts writes: reachable, and not a read-only replica (an Aurora Global
    Database secondary reports `pg_is_in_recovery()` until it is promoted)."""

    def check() -> bool:
        with pool.connection(timeout=timeout) as conn:
            conn.execute("SELECT set_config('statement_timeout', %s, true)", (str(int(timeout * 1000)),))
            return not conn.execute("SELECT pg_is_in_recovery()").fetchone()[0]

    return check
