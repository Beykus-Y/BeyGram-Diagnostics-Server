"""Скользящее окно rate limit на таблице rate_events.

Счётчики строятся по событиям в окне (а не по фиксированным бакетам), что
даёт корректное поведение на границах минут/суток. Ключи псевдонимизированы:
для IP хранится HMAC-хэш, а не сырой адрес.
"""

from __future__ import annotations

import sqlite3

from ..util import now

SCOPE_USER_REPORT_CMD = "user_report_cmd"
SCOPE_GLOBAL_REPORT_CMD = "global_report_cmd"
SCOPE_USER_REPORT = "user_report"
SCOPE_IP_REPORT = "ip_report"
SCOPE_GLOBAL_REPORT = "global_report"


def record(conn: sqlite3.Connection, scope: str, key: str, *, at: float | None = None) -> None:
    conn.execute(
        "INSERT INTO rate_events (scope, key, at) VALUES (?, ?, ?)",
        (scope, key, at if at is not None else now()),
    )


def count_since(conn: sqlite3.Connection, scope: str, key: str, since: float) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM rate_events WHERE scope = ? AND key = ? AND at >= ?",
        (scope, key, since),
    ).fetchone()
    return int(row["c"]) if row else 0


def count_global_since(conn: sqlite3.Connection, scope: str, since: float) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM rate_events WHERE scope = ? AND at >= ?",
        (scope, since),
    ).fetchone()
    return int(row["c"]) if row else 0


def check_and_record(
    conn: sqlite3.Connection,
    *,
    scope: str,
    key: str | None,
    limit: int,
    window_seconds: int,
    at: float | None = None,
) -> tuple[bool, float]:
    """Проверяет лимит и, если он не превышен, сразу фиксирует событие.

    Возвращает (allowed, retry_after_seconds). Когда ключ None, считается
    глобальный лимит по scope (без учёта key).
    """
    ts = at if at is not None else now()
    since = ts - window_seconds

    if key is None:
        used = count_global_since(conn, scope, since)
        oldest_sql = "SELECT MIN(at) AS m FROM rate_events WHERE scope = ? AND at >= ?"
        row = conn.execute(oldest_sql, (scope, since)).fetchone()
    else:
        used = count_since(conn, scope, key, since)
        row = conn.execute(
            "SELECT MIN(at) AS m FROM rate_events WHERE scope = ? AND key = ? AND at >= ?",
            (scope, key, since),
        ).fetchone()

    if used >= limit:
        oldest = float(row["m"]) if row and row["m"] is not None else ts
        retry_after = max(1.0, (oldest + window_seconds) - ts)
        return False, retry_after

    record(conn, scope, key if key is not None else "*", at=ts)
    return True, 0.0


def peek(
    conn: sqlite3.Connection,
    *,
    scope: str,
    key: str | None,
    limit: int,
    window_seconds: int,
    at: float | None = None,
) -> tuple[bool, float]:
    """Проверка лимита без записи события."""
    ts = at if at is not None else now()
    since = ts - window_seconds

    if key is None:
        used = count_global_since(conn, scope, since)
        row = conn.execute(
            "SELECT MIN(at) AS m FROM rate_events WHERE scope = ? AND at >= ?", (scope, since)
        ).fetchone()
    else:
        used = count_since(conn, scope, key, since)
        row = conn.execute(
            "SELECT MIN(at) AS m FROM rate_events WHERE scope = ? AND key = ? AND at >= ?",
            (scope, key, since),
        ).fetchone()

    if used >= limit:
        oldest = float(row["m"]) if row and row["m"] is not None else ts
        return False, max(1.0, (oldest + window_seconds) - ts)
    return True, 0.0


def prune(conn: sqlite3.Connection, *, keep_seconds: int, at: float | None = None) -> int:
    ts = at if at is not None else now()
    cur = conn.execute("DELETE FROM rate_events WHERE at < ?", (ts - keep_seconds,))
    return cur.rowcount
