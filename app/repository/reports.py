"""Репозиторий отчётов: очередь доставки, идемпотентность, ретраи.

Идемпотентность устроена так:
* report_id — первичный ключ; повторный POST c тем же report_id и тем же
  fingerprint содержимого возвращает исходный результат, а не создаёт дубль;
* повторный POST c тем же report_id, но другим содержимым → 409;
* воркер забирает работу через lease (PROCESSING + lease_until), что защищает
  от параллельной доставки одного отчёта несколькими процессами.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from ..state import (
    REPORT_DELIVERED,
    REPORT_DROPPED,
    REPORT_FAILED,
    REPORT_PROCESSING,
    REPORT_QUEUED,
)
from ..util import now


@dataclass(frozen=True)
class ReportRecord:
    report_id: str
    telegram_user_id: int
    nonce_hash: str
    status: str
    description: str
    summary: str | None
    events_json: str
    client_meta_json: str | None
    payload_fingerprint: str
    body_bytes: int
    app_version: str | None
    attempts: int
    max_attempts: int
    next_attempt_at: float | None
    lease_until: float | None
    delivery_message_id: int | None
    last_error: str | None
    created_at: float
    updated_at: float
    delivered_at: float | None
    expires_at: float | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> ReportRecord:
        return cls(
            report_id=row["report_id"],
            telegram_user_id=int(row["telegram_user_id"]),
            nonce_hash=row["nonce_hash"],
            status=row["status"],
            description=row["description"],
            summary=row["summary"],
            events_json=row["events_json"],
            client_meta_json=row["client_meta_json"],
            payload_fingerprint=row["payload_fingerprint"],
            body_bytes=int(row["body_bytes"]),
            app_version=row["app_version"],
            attempts=int(row["attempts"]),
            max_attempts=int(row["max_attempts"]),
            next_attempt_at=row["next_attempt_at"],
            lease_until=row["lease_until"],
            delivery_message_id=row["delivery_message_id"],
            last_error=row["last_error"],
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            delivered_at=row["delivered_at"],
            expires_at=row["expires_at"],
        )

    def events(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self.events_json)
        except (TypeError, ValueError):
            return []
        return data if isinstance(data, list) else []

    def client_meta(self) -> dict[str, Any]:
        if not self.client_meta_json:
            return {}
        try:
            data = json.loads(self.client_meta_json)
        except (TypeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}


def get(conn: sqlite3.Connection, report_id: str) -> ReportRecord | None:
    row = conn.execute("SELECT * FROM reports WHERE report_id = ?", (report_id,)).fetchone()
    return ReportRecord.from_row(row) if row else None


def insert(
    conn: sqlite3.Connection,
    *,
    report_id: str,
    telegram_user_id: int,
    nonce_hash: str,
    description: str,
    summary: str | None,
    events: list[dict[str, Any]],
    client_meta: dict[str, Any] | None,
    payload_fingerprint: str,
    body_bytes: int,
    app_version: str | None,
    max_attempts: int,
    retention_days: int,
    at: float | None = None,
) -> ReportRecord:
    """Создаёт отчёт в состоянии QUEUED. Ожидает уже открытой транзакции."""
    ts = at if at is not None else now()
    conn.execute(
        """
        INSERT INTO reports (
            report_id, telegram_user_id, nonce_hash, status, description, summary,
            events_json, client_meta_json, payload_fingerprint, body_bytes, app_version,
            attempts, max_attempts, next_attempt_at, lease_until, delivery_message_id,
            last_error, created_at, updated_at, delivered_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, NULL, NULL, NULL, ?, ?, NULL, ?)
        """,
        (
            report_id,
            telegram_user_id,
            nonce_hash,
            REPORT_QUEUED,
            description,
            summary,
            json.dumps(events, ensure_ascii=False, separators=(",", ":")),
            json.dumps(client_meta, ensure_ascii=False, separators=(",", ":")) if client_meta else None,
            payload_fingerprint,
            body_bytes,
            app_version,
            max_attempts,
            ts,
            ts,
            ts,
            ts + retention_days * 86400,
        ),
    )
    record = get(conn, report_id)
    assert record is not None
    return record


def claim_next_for_delivery(
    conn: sqlite3.Connection,
    *,
    lease_seconds: int,
    at: float | None = None,
) -> ReportRecord | None:
    """Атомарно забирает следующий отчёт к доставке.

    Берём самый старый QUEUED, готовый по времени (next_attempt_at <= now), и
    помечаем PROCESSING с lease. При падении воркера lease истечёт и отчёт
    вернётся в очередь через requeue_expired_leases().
    """
    ts = at if at is not None else now()
    row = conn.execute(
        """
        SELECT report_id FROM reports
         WHERE status = ?
           AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
         ORDER BY created_at ASC
         LIMIT 1
        """,
        (REPORT_QUEUED, ts),
    ).fetchone()
    if row is None:
        return None

    cur = conn.execute(
        """
        UPDATE reports
           SET status = ?, lease_until = ?, attempts = attempts + 1, updated_at = ?
         WHERE report_id = ? AND status = ?
        """,
        (REPORT_PROCESSING, ts + lease_seconds, ts, row["report_id"], REPORT_QUEUED),
    )
    if cur.rowcount != 1:
        return None
    return get(conn, row["report_id"])


def mark_delivered(
    conn: sqlite3.Connection,
    report_id: str,
    *,
    message_id: int | None,
    at: float | None = None,
) -> None:
    ts = at if at is not None else now()
    conn.execute(
        """
        UPDATE reports
           SET status = ?, delivered_at = ?, updated_at = ?, lease_until = NULL,
               next_attempt_at = NULL, delivery_message_id = ?, last_error = NULL
         WHERE report_id = ?
        """,
        (REPORT_DELIVERED, ts, ts, message_id, report_id),
    )


def schedule_retry(
    conn: sqlite3.Connection,
    report_id: str,
    *,
    error: str,
    delay_seconds: float,
    at: float | None = None,
) -> str:
    """Планирует повторную попытку либо помечает FAILED при исчерпании.

    Возвращает новое состояние отчёта.
    """
    ts = at if at is not None else now()
    record = get(conn, report_id)
    if record is None:
        return REPORT_FAILED

    if record.attempts >= record.max_attempts:
        conn.execute(
            """
            UPDATE reports
               SET status = ?, last_error = ?, updated_at = ?, lease_until = NULL
             WHERE report_id = ?
            """,
            (REPORT_FAILED, error[:1000], ts, report_id),
        )
        return REPORT_FAILED

    conn.execute(
        """
        UPDATE reports
           SET status = ?, last_error = ?, next_attempt_at = ?, lease_until = NULL, updated_at = ?
         WHERE report_id = ?
        """,
        (REPORT_QUEUED, error[:1000], ts + delay_seconds, ts, report_id),
    )
    return REPORT_QUEUED


def requeue_expired_leases(conn: sqlite3.Connection, *, at: float | None = None) -> int:
    """Возвращает в очередь отчёты, чей lease истёк (воркер упал)."""
    ts = at if at is not None else now()
    cur = conn.execute(
        """
        UPDATE reports
           SET status = ?, lease_until = NULL, updated_at = ?
         WHERE status = ?
           AND lease_until IS NOT NULL
           AND lease_until <= ?
        """,
        (REPORT_QUEUED, ts, REPORT_PROCESSING, ts),
    )
    return cur.rowcount


def drop_pending(conn: sqlite3.Connection, *, reason: str, at: float | None = None) -> int:
    """Снимает с доставки всё, что ещё не отправлено (kill switch / отзыв)."""
    ts = at if at is not None else now()
    cur = conn.execute(
        """
        UPDATE reports
           SET status = ?, last_error = ?, updated_at = ?, lease_until = NULL
         WHERE status IN (?, ?)
        """,
        (REPORT_DROPPED, reason[:1000], ts, REPORT_QUEUED, REPORT_PROCESSING),
    )
    return cur.rowcount


def drop_pending_for_user(
    conn: sqlite3.Connection,
    telegram_user_id: int,
    *,
    reason: str,
    at: float | None = None,
) -> int:
    ts = at if at is not None else now()
    cur = conn.execute(
        """
        UPDATE reports
           SET status = ?, last_error = ?, updated_at = ?, lease_until = NULL
         WHERE telegram_user_id = ?
           AND status IN (?, ?)
        """,
        (REPORT_DROPPED, reason[:1000], ts, telegram_user_id, REPORT_QUEUED, REPORT_PROCESSING),
    )
    return cur.rowcount


def queue_stats(conn: sqlite3.Connection) -> dict[str, int]:
    rows = conn.execute("SELECT status, COUNT(*) AS c FROM reports GROUP BY status").fetchall()
    stats = {row["status"]: int(row["c"]) for row in rows}
    overdue = conn.execute(
        "SELECT COUNT(*) AS c FROM reports WHERE status = ? AND attempts > 0",
        (REPORT_QUEUED,),
    ).fetchone()
    stats["queued_retrying"] = int(overdue["c"]) if overdue else 0
    return stats


def queue_depth(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM reports WHERE status IN (?, ?)",
        (REPORT_QUEUED, REPORT_PROCESSING),
    ).fetchone()
    return int(row["c"]) if row else 0


def delete_older_than(conn: sqlite3.Connection, cutoff: float) -> int:
    """Удаляет доставленные/проваленные/снятые отчёты старше cutoff."""
    cur = conn.execute(
        """
        DELETE FROM reports
         WHERE status IN (?, ?, ?)
           AND COALESCE(delivered_at, updated_at) < ?
        """,
        (REPORT_DELIVERED, REPORT_FAILED, REPORT_DROPPED, cutoff),
    )
    return cur.rowcount


def count_for_user_since(conn: sqlite3.Connection, telegram_user_id: int, since: float) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM reports WHERE telegram_user_id = ? AND created_at >= ?",
        (telegram_user_id, since),
    ).fetchone()
    return int(row["c"]) if row else 0
