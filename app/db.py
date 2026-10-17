"""Слой доступа к SQLite (WAL) с миграциями.

Модель конкурентности:
* SQLite в режиме WAL допускает много читателей и одного писателя;
* сервер держит одно соединение и сериализует все операции через asyncio.Lock,
  поэтому транзакции (atomic claim, идемпотентность, лимиты) не пересекаются;
* операции локального SQLite с WAL выполняются за доли миллисекунды, поэтому
  выполнение их в event loop допустимо для нагрузки закрытой беты.

Если проект вырастет, этот модуль — единственное место, которое нужно
переписать на пool соединений / Postgres.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager, suppress
from typing import Any

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1

_DDL_V1 = """
CREATE TABLE IF NOT EXISTS allowlist (
    telegram_user_id  INTEGER PRIMARY KEY,
    label             TEXT    NOT NULL DEFAULT '',
    active            INTEGER NOT NULL DEFAULT 1,
    created_at        REAL    NOT NULL,
    updated_at        REAL    NOT NULL,
    revoked_at        REAL,
    revoked_reason    TEXT
);

CREATE TABLE IF NOT EXISTS nonces (
    nonce_hash          TEXT    PRIMARY KEY,
    telegram_user_id    INTEGER NOT NULL,
    state               TEXT    NOT NULL,
    report_id           TEXT,
    request_fingerprint TEXT,
    issued_at           REAL    NOT NULL,
    expires_at          REAL    NOT NULL,
    claimed_at          REAL,
    delivered_at        REAL
);
CREATE INDEX IF NOT EXISTS idx_nonces_expires ON nonces(expires_at);
CREATE INDEX IF NOT EXISTS idx_nonces_state   ON nonces(state);
CREATE INDEX IF NOT EXISTS idx_nonces_report  ON nonces(report_id);
CREATE INDEX IF NOT EXISTS idx_nonces_user    ON nonces(telegram_user_id, issued_at);

CREATE TABLE IF NOT EXISTS reports (
    report_id           TEXT    PRIMARY KEY,
    telegram_user_id    INTEGER NOT NULL,
    nonce_hash          TEXT    NOT NULL,
    status              TEXT    NOT NULL,
    description         TEXT    NOT NULL,
    summary             TEXT,
    events_json         TEXT    NOT NULL,
    client_meta_json    TEXT,
    payload_fingerprint TEXT    NOT NULL,
    body_bytes          INTEGER NOT NULL,
    app_version         TEXT,
    attempts            INTEGER NOT NULL DEFAULT 0,
    max_attempts        INTEGER NOT NULL DEFAULT 6,
    next_attempt_at     REAL,
    lease_until         REAL,
    delivery_message_id INTEGER,
    last_error          TEXT,
    created_at          REAL    NOT NULL,
    updated_at          REAL    NOT NULL,
    delivered_at        REAL,
    expires_at          REAL
);
CREATE INDEX IF NOT EXISTS idx_reports_queue ON reports(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_reports_user  ON reports(telegram_user_id, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_nonce ON reports(nonce_hash);

CREATE TABLE IF NOT EXISTS rate_events (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL,
    key   TEXT NOT NULL,
    at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_lookup ON rate_events(scope, key, at);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        REAL NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT,
    detail    TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);

CREATE TABLE IF NOT EXISTS kv (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at REAL NOT NULL
);
"""

_MIGRATIONS: tuple[tuple[int, str], ...] = ((1, _DDL_V1),)


class Database:
    """Асинхронная обёртка над единственным соединением SQLite."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    # --- Жизненный цикл ------------------------------------------------------

    @property
    def path(self) -> str:
        return self._path

    @property
    def connection(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Database is not connected; call connect() first")
        return self._conn

    def connect(self) -> None:
        """Открывает соединение и применяет миграции (синхронно, при старте)."""
        directory = os.path.dirname(os.path.abspath(self._path))
        if directory:
            os.makedirs(directory, exist_ok=True)

        conn = sqlite3.connect(
            self._path,
            isolation_level=None,
            timeout=10.0,
            # Доступ сериализуется asyncio.Lock, а соединение живёт в потоке
            # event loop; разрешаем использование из потока, где создан, и из
            # вызывающего (CLI/тесты) — конкурентность исключена локом.
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        self._conn = conn

        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA wal_autocheckpoint=512")

        self._migrate()
        log.info("database ready", extra={"path": self._path, "schema_version": SCHEMA_VERSION})

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def _migrate(self) -> None:
        conn = self.connection
        conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
        row = conn.execute("SELECT version FROM schema_version").fetchone()
        current = int(row["version"]) if row else 0

        if current > SCHEMA_VERSION:
            raise RuntimeError(
                f"Database schema version {current} is newer than supported {SCHEMA_VERSION}"
            )

        for version, ddl in _MIGRATIONS:
            if version <= current:
                continue
            log.info("applying migration", extra={"version": version})
            # executescript сам управляет транзакцией (неявный COMMIT перед
            # выполнением), поэтому его нельзя оборачивать в BEGIN IMMEDIATE.
            # DDL в SQLite транзакционен, поэтому при падении на середине
            # схема не будет помечена как применённая.
            conn.executescript("BEGIN;\n" + ddl + "\nCOMMIT;")
            if row is None:
                conn.execute("INSERT INTO schema_version(version) VALUES (?)", (version,))
                row = True
            else:
                conn.execute("UPDATE schema_version SET version = ?", (version,))
            current = version

    # --- Низкоуровневый доступ ----------------------------------------------

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Транзакция BEGIN IMMEDIATE: писательский лок берётся сразу.

        IMMEDIATE выбран намеренно: он сериализует «проверить-и-изменить» и
        превращает гонки (двойной claim nonce, двойная постановка в очередь)
        в предсказуемый конфликт на уровне SQLite, а не в тихую потерю данных.
        """
        conn = self.connection
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except Exception:
            # ROLLBACK защищаем: если транзакция уже завершилась внутри блока
            # (например, из-за DDL), повторный откат не должен маскировать
            # исходную ошибку.
            with suppress(sqlite3.OperationalError):
                conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        return self.connection.execute(sql, params)

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        return self.connection.execute(sql, params).fetchone()

    def query_all(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        return list(self.connection.execute(sql, params).fetchall())

    def executemany(self, sql: str, rows: Iterable[Sequence[Any]]) -> None:
        self.connection.executemany(sql, rows)

    # --- Асинхронные операции ------------------------------------------------

    async def run(self, fn, *args, **kwargs):
        """Выполняет операцию под общим локом (сериализация доступа).

        Функция может свободно открывать несколько транзакций подряд —
        лок гарантирует, что между ними не вклинится другая операция.
        """
        async with self._lock:
            return fn(*args, **kwargs)

    async def checkpoint(self) -> None:
        """Явный WAL-checkpoint: полезно перед бэкапом и при простое."""

        def _do() -> None:
            self.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        await self.run(_do)

    def integrity_check(self) -> str:
        row = self.query_one("PRAGMA integrity_check")
        return str(row[0]) if row else "unknown"
