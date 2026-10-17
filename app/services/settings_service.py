"""Рантайм-настройки: выключатель приёма и вспомогательные операции.

Помимо конфигурации из окружения есть динамический выключатель приёма,
который можно переключать без перезапуска (CLI). Он хранится в kv.
"""

from __future__ import annotations

import sqlite3

from ..config import Settings
from ..db import Database
from ..repository import audit, kv


def intake_enabled(conn: sqlite3.Connection, settings: Settings) -> bool:
    """Приём включён, только если разрешено и конфигурацией, и выключателем."""
    if not settings.accept_reports:
        return False
    return kv.get_bool(conn, kv.KEY_ACCEPT_REPORTS, True)


def set_intake_enabled(
    conn: sqlite3.Connection,
    enabled: bool,
    *,
    actor: str,
    note: str = "",
) -> None:
    kv.set_value(conn, kv.KEY_ACCEPT_REPORTS, "true" if enabled else "false")
    if note:
        kv.set_value(conn, kv.KEY_INTAKE_NOTE, note)
    audit.write(
        conn,
        actor=actor,
        action="intake_enabled" if enabled else "intake_disabled",
        target="global",
        detail={"note": note},
    )


def get_intake_note(conn: sqlite3.Connection) -> str:
    return kv.get_value(conn, kv.KEY_INTAKE_NOTE) or ""


async def set_intake(db: Database, enabled: bool, *, actor: str, note: str = "") -> None:
    def _do() -> None:
        with db.transaction() as conn:
            set_intake_enabled(conn, enabled, actor=actor, note=note)

    await db.run(_do)
