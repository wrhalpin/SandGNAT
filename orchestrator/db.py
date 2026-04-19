# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Postgres connection pool.

All SQL in the orchestrator goes through this module via `persistence.py`.
Parsers and builders stay pure.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from psycopg import Connection
from psycopg_pool import ConnectionPool

from .config import get_settings

_pool: ConnectionPool | None = None


def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        settings = get_settings()
        _pool = ConnectionPool(
            conninfo=settings.database_url,
            min_size=1,
            max_size=max(settings.max_concurrent_analyses * 2, 4),
            kwargs={"autocommit": False},
        )
    return _pool


@contextmanager
def connection() -> Iterator[Connection]:
    """Yield a pooled connection. Commits on success, rolls back on exception."""
    pool = get_pool()
    with pool.connection() as conn:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None
