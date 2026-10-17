"""Аудит административных и значимых действий.

В аудит никогда не пишутся сырые nonce и токены — только хэши и id.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from ..util import now


@dataclass(frozen=True)
class AuditEntry:
    id: int
    at: float
    actor: str
    action: str
    target: str | None
    detail: dict[str, Any]


def write(
    conn: sqlite3.Connection,
    *,
    actor: str,
    action: str,
    target: str | None = None,
    detail: dict[str, Any] | None = None,
    at: float | None = None,
) -> None:
    conn.execute(
        "INSERT INTO audit_log (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
        (
            at if at is not None else now(),
            actor,
            action,
            target,
            json.dumps(detail or {}, ensure_ascii=False, separators=(",", ":")),
        ),
    )


def recent(conn: sqlite3.Connection, *, limit: int = 100) -> list[AuditEntry]:
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    entries: list[AuditEntry] = []
    for row in rows:
        try:
            detail = json.loads(row["detail"] or "{}")
        except ValueError:
            detail = {}
        entries.append(
            AuditEntry(
                id=int(row["id"]),
                at=float(row["at"]),
                actor=row["actor"],
                action=row["action"],
                target=row["target"],
                detail=detail if isinstance(detail, dict) else {},
            )
        )
    return entries


def prune(conn: sqlite3.Connection, *, keep_seconds: int, at: float | None = None) -> int:
    ts = at if at is not None else now()
    cur = conn.execute("DELETE FROM audit_log WHERE at < ?", (ts - keep_seconds,))
    return cur.rowcount
