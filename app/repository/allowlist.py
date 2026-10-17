"""Список доступа тестировщиков (allowlist по Telegram user id).

Отозванные записи не удаляются: `active=0` сохраняет историю и позволяет
объяснить клиенту отказ, не раскрывая сам факт нахождения в списке
неавторизованному наблюдателю.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from ..util import now


@dataclass(frozen=True)
class AllowlistEntry:
    telegram_user_id: int
    label: str
    active: bool
    created_at: float
    updated_at: float
    revoked_at: float | None
    revoked_reason: str | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> AllowlistEntry:
        return cls(
            telegram_user_id=int(row["telegram_user_id"]),
            label=row["label"] or "",
            active=bool(row["active"]),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            revoked_at=row["revoked_at"],
            revoked_reason=row["revoked_reason"],
        )


def add(
    conn: sqlite3.Connection,
    telegram_user_id: int,
    *,
    label: str = "",
    at: float | None = None,
) -> AllowlistEntry:
    """Добавляет пользователя или реактивирует ранее отозванного."""
    ts = at if at is not None else now()
    conn.execute(
        """
        INSERT INTO allowlist (telegram_user_id, label, active, created_at, updated_at)
        VALUES (?, ?, 1, ?, ?)
        ON CONFLICT(telegram_user_id) DO UPDATE SET
            label = excluded.label,
            active = 1,
            updated_at = excluded.updated_at,
            revoked_at = NULL,
            revoked_reason = NULL
        """,
        (telegram_user_id, label, ts, ts),
    )
    entry = get(conn, telegram_user_id)
    assert entry is not None
    return entry


def revoke(
    conn: sqlite3.Connection,
    telegram_user_id: int,
    *,
    reason: str = "",
    at: float | None = None,
) -> bool:
    """Отзывает доступ. Возвращает True, если запись была активна."""
    ts = at if at is not None else now()
    cur = conn.execute(
        """
        UPDATE allowlist
           SET active = 0, revoked_at = ?, revoked_reason = ?, updated_at = ?
         WHERE telegram_user_id = ? AND active = 1
        """,
        (ts, reason, ts, telegram_user_id),
    )
    return cur.rowcount > 0


def get(conn: sqlite3.Connection, telegram_user_id: int) -> AllowlistEntry | None:
    row = conn.execute(
        "SELECT * FROM allowlist WHERE telegram_user_id = ?", (telegram_user_id,)
    ).fetchone()
    return AllowlistEntry.from_row(row) if row else None


def is_active(conn: sqlite3.Connection, telegram_user_id: int) -> bool:
    row = conn.execute(
        "SELECT active FROM allowlist WHERE telegram_user_id = ?", (telegram_user_id,)
    ).fetchone()
    return bool(row and row["active"])


def list_all(conn: sqlite3.Connection, *, active_only: bool = False) -> list[AllowlistEntry]:
    sql = "SELECT * FROM allowlist"
    if active_only:
        sql += " WHERE active = 1"
    sql += " ORDER BY created_at ASC"
    return [AllowlistEntry.from_row(r) for r in conn.execute(sql).fetchall()]


def seed(conn: sqlite3.Connection, telegram_user_ids: set[int], *, label: str = "bootstrap") -> int:
    """Идемпотентно добавляет набор id (используется при старте из BOOTSTRAP_ALLOWLIST)."""
    added = 0
    for user_id in sorted(telegram_user_ids):
        existing = get(conn, user_id)
        if existing is None:
            add(conn, user_id, label=label)
            added += 1
    return added


def count_entries(conn: sqlite3.Connection) -> dict[str, Any]:
    row = conn.execute(
        "SELECT COUNT(*) AS total, SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) AS active FROM allowlist"
    ).fetchone()
    return {"total": int(row["total"] or 0), "active": int(row["active"] or 0)}
