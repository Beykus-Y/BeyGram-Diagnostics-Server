"""Простое key/value-хранилище для рантайм-настроек (kill switch и пр.)."""

from __future__ import annotations

import sqlite3

from ..util import now

KEY_ACCEPT_REPORTS = "accept_reports"
KEY_INTAKE_NOTE = "intake_note"
KEY_BOT_LAST_UPDATE = "bot_last_update_id"


def set_value(conn: sqlite3.Connection, key: str, value: str, *, at: float | None = None) -> None:
    conn.execute(
        """
        INSERT INTO kv (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """,
        (key, value, at if at is not None else now()),
    )


def get_value(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def get_bool(conn: sqlite3.Connection, key: str, default: bool) -> bool:
    value = get_value(conn, key)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def delete(conn: sqlite3.Connection, key: str) -> bool:
    """Удаляет ключ. Возвращает True, если ключ существовал."""
    cur = conn.execute("DELETE FROM kv WHERE key = ?", (key,))
    return cur.rowcount > 0
