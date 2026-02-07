from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterator

try:
    import psycopg  # type: ignore
except Exception:  # pragma: no cover - exercised only when dependency is missing
    psycopg = None

DATABASE_URL_ENV = "DATABASE_URL"
DEFAULT_DATABASE_URL = "postgresql://zt_user:zt_pass@localhost:5432/zt_api"


def get_database_url() -> str:
    return os.getenv(DATABASE_URL_ENV, DEFAULT_DATABASE_URL)


def _require_psycopg() -> Any:
    if psycopg is None:
        raise RuntimeError("psycopg is required for database access. Install psycopg[binary].")
    return psycopg


@contextmanager
def open_connection(database_url: str | None = None) -> Iterator[Any]:
    driver = _require_psycopg()
    connection = driver.connect(database_url or get_database_url())
    try:
        yield connection
    finally:
        connection.close()


def fetch_resources_for_tenant(
    tenant_id: str,
    limit: int = 100,
    database_url: str | None = None,
) -> list[dict[str, Any]]:
    """
    Tenant-scoped read helper. `tenant_id` is mandatory and always enforced in SQL.
    """
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("tenant_id is required")

    safe_limit = max(1, min(int(limit), 1000))
    query = """
        SELECT id, tenant_id, name, classification, created_at
        FROM resources
        WHERE tenant_id = %s
        ORDER BY id ASC
        LIMIT %s
    """

    with open_connection(database_url=database_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, (tenant_id, safe_limit))
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description or []]

    return [dict(zip(columns, row)) for row in rows]
