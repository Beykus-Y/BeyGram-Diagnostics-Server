"""Репозиторий одноразовых токенов (nonce).

Сырой nonce здесь не появляется никогда — таблица ключуется HMAC-хэшем.
Ключевая операция — claim(): атомарный переход ISSUED → PROCESSING с
одновременной привязкой к report_id. Он выполняется под BEGIN IMMEDIATE,
поэтому двойная отправка не создаёт двух отчётов.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from ..state import (
    NONCE_ACCEPTED,
    NONCE_DELIVERED,
    NONCE_EXPIRED,
    NONCE_ISSUED,
    NONCE_PROCESSING,
    NONCE_REVOKED,
)
from ..util import now


@dataclass(frozen=True)
class NonceRecord:
    nonce_hash: str
    telegram_user_id: int
    state: str
    report_id: str | None
    request_fingerprint: str | None
    issued_at: float
    expires_at: float
    claimed_at: float | None
    delivered_at: float | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> NonceRecord:
        keys = row.keys()
        return cls(
            nonce_hash=row["nonce_hash"],
            telegram_user_id=int(row["telegram_user_id"]),
            state=row["state"],
            report_id=row["report_id"],
            request_fingerprint=row["request_fingerprint"],
            issued_at=float(row["issued_at"]),
            expires_at=float(row["expires_at"]),
            claimed_at=row["claimed_at"] if "claimed_at" in keys else None,
            delivered_at=row["delivered_at"] if "delivered_at" in keys else None,
        )

    @property
    def is_live(self) -> bool:
        return self.state in {NONCE_ISSUED, NONCE_PROCESSING, NONCE_ACCEPTED}


def _select(conn: sqlite3.Connection, where: str, params: tuple) -> NonceRecord | None:
    row = conn.execute(f"SELECT * FROM nonces WHERE {where}", params).fetchone()
    return NonceRecord.from_row(row) if row else None


def get(conn: sqlite3.Connection, nonce_hash: str) -> NonceRecord | None:
    return _select(conn, "nonce_hash = ?", (nonce_hash,))


def get_by_report_id(conn: sqlite3.Connection, report_id: str) -> NonceRecord | None:
    return _select(conn, "report_id = ?", (report_id,))


def register_issued(
    conn: sqlite3.Connection,
    *,
    nonce_hash: str,
    telegram_user_id: int,
    ttl_seconds: int,
    at: float | None = None,
) -> tuple[NonceRecord, bool]:
    """Регистрирует nonce как ISSUED. Идемпотентно для повторных /report.

    Возвращает (запись, created). created=False означает, что запись уже
    существовала в живом состоянии у того же пользователя — повторная команда
    /report тем же nonce не должна ничего ломать.
    Повторное использование хэша другим пользователем отклоняется.
    """
    ts = at if at is not None else now()
    expires_at = ts + ttl_seconds

    existing = get(conn, nonce_hash)
    if existing is not None:
        if existing.telegram_user_id != telegram_user_id:
            raise NonceConflictError("nonce hash already registered to another user")
        if existing.is_live:
            return existing, False
        # Просроченный/погашенный/отозванный nonce переиспользовать нельзя.
        raise NonceConflictError("nonce already consumed")

    conn.execute(
        """
        INSERT INTO nonces
            (nonce_hash, telegram_user_id, state, report_id, request_fingerprint,
             issued_at, expires_at, claimed_at, delivered_at)
        VALUES (?, ?, ?, NULL, NULL, ?, ?, NULL, NULL)
        """,
        (nonce_hash, telegram_user_id, NONCE_ISSUED, ts, expires_at),
    )
    record = get(conn, nonce_hash)
    assert record is not None
    return record, True


def claim(
    conn: sqlite3.Connection,
    *,
    nonce_hash: str,
    telegram_user_id: int,
    report_id: str,
    request_fingerprint: str,
    at: float | None = None,
) -> NonceRecord | None:
    """Атомарно привязывает nonce к report_id (ISSUED → PROCESSING).

    Возвращает обновлённую запись при успехе либо None, если переход
    невозможен (токен уже использован/просрочен/принадлежит другому
    пользователю). Вызывать только внутри db.transaction().
    """
    ts = at if at is not None else now()
    cur = conn.execute(
        """
        UPDATE nonces
           SET state = ?,
               report_id = ?,
               request_fingerprint = ?,
               claimed_at = ?
         WHERE nonce_hash = ?
           AND state = ?
           AND telegram_user_id = ?
           AND expires_at > ?
        """,
        (
            NONCE_PROCESSING,
            report_id,
            request_fingerprint,
            ts,
            nonce_hash,
            NONCE_ISSUED,
            telegram_user_id,
            ts,
        ),
    )
    if cur.rowcount != 1:
        return None
    return get(conn, nonce_hash)


def set_state(
    conn: sqlite3.Connection,
    nonce_hash: str,
    state: str,
    *,
    delivered_at: float | None = None,
) -> None:
    if delivered_at is not None:
        conn.execute(
            "UPDATE nonces SET state = ?, delivered_at = ? WHERE nonce_hash = ?",
            (state, delivered_at, nonce_hash),
        )
    else:
        conn.execute("UPDATE nonces SET state = ? WHERE nonce_hash = ?", (state, nonce_hash))


def mark_accepted(conn: sqlite3.Connection, nonce_hash: str) -> None:
    set_state(conn, nonce_hash, NONCE_ACCEPTED)


def mark_delivered(conn: sqlite3.Connection, nonce_hash: str, *, at: float | None = None) -> None:
    set_state(conn, nonce_hash, NONCE_DELIVERED, delivered_at=at if at is not None else now())


def expire_stale(conn: sqlite3.Connection, *, at: float | None = None) -> int:
    """Помечает EXPIRED только непривязанные ISSUED nonce с истёкшим TTL.

    Nonce, уже привязанные к отчёту (PROCESSING/ACCEPTED), TTL не гасятся:
    идемпотентный повтор POST того же отчёта должен работать и после истечения
    TTL (потерянный HTTP-ответ), пока отчёт жив в базе.
    """
    ts = at if at is not None else now()
    cur = conn.execute(
        """
        UPDATE nonces
           SET state = ?
         WHERE expires_at <= ?
           AND state = ?
        """,
        (NONCE_EXPIRED, ts, NONCE_ISSUED),
    )
    return cur.rowcount


def delete_orphaned_bound(conn: sqlite3.Connection, cutoff: float) -> int:
    """Удаляет привязанные nonce, чей отчёт уже удалён (retention).

    Идемпотентный повтор для удалённого отчёта всё равно дал бы 401, поэтому
    хранить такие nonce бессмысленно; cutoff не даёт трогать свежие записи.
    """
    cur = conn.execute(
        """
        DELETE FROM nonces
         WHERE state IN (?, ?)
           AND claimed_at IS NOT NULL
           AND claimed_at < ?
           AND report_id IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM reports WHERE reports.report_id = nonces.report_id)
        """,
        (NONCE_PROCESSING, NONCE_ACCEPTED, cutoff),
    )
    return cur.rowcount


def revoke_for_user(conn: sqlite3.Connection, telegram_user_id: int) -> int:
    """Отзывает живые nonce пользователя (удаление из allowlist / kill switch)."""
    cur = conn.execute(
        """
        UPDATE nonces
           SET state = ?
         WHERE telegram_user_id = ?
           AND state IN (?, ?, ?)
        """,
        (
            NONCE_REVOKED,
            telegram_user_id,
            NONCE_ISSUED,
            NONCE_PROCESSING,
            NONCE_ACCEPTED,
        ),
    )
    return cur.rowcount


def delete_terminal_older_than(conn: sqlite3.Connection, cutoff: float) -> int:
    """Удаляет погашенные/просроченные/отозванные nonce старше cutoff."""
    cur = conn.execute(
        """
        DELETE FROM nonces
         WHERE state IN (?, ?, ?)
           AND COALESCE(delivered_at, claimed_at, issued_at) < ?
        """,
        (NONCE_DELIVERED, NONCE_EXPIRED, NONCE_REVOKED, cutoff),
    )
    return cur.rowcount


def count_by_state(conn: sqlite3.Connection) -> dict[str, int]:
    rows = conn.execute("SELECT state, COUNT(*) AS c FROM nonces GROUP BY state").fetchall()
    return {row["state"]: int(row["c"]) for row in rows}


class NonceConflictError(Exception):
    """Хэш nonce уже занят и не может быть переиспользован."""
