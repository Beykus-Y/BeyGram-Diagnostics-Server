"""Схема отдельной SQLite-базы BG Push.

База версионируется независимо от основной (PUSH_SCHEMA_VERSION), поэтому
сбой или откат BG Push не затрагивает отчёты и аналитику.
"""

from __future__ import annotations

PUSH_SCHEMA_VERSION = 1

_DDL_V1 = """
CREATE TABLE IF NOT EXISTS push_registrations (
    registration_id       TEXT PRIMARY KEY,
    state                 TEXT NOT NULL CHECK (state IN ('pending', 'active', 'revoked', 'expired')),
    platform              TEXT NOT NULL DEFAULT 'ios_pwa',
    owner_digest          TEXT NOT NULL,
    pairing_digest        TEXT,
    token_digest          TEXT,
    capability_digest     TEXT NOT NULL UNIQUE,
    endpoint_host         TEXT,
    endpoint_sealed       TEXT,
    p256dh_sealed         TEXT,
    auth_sealed           TEXT,
    ingress_p256dh        TEXT,
    ingress_auth_sealed   TEXT,
    pairing_expires_at    REAL NOT NULL,
    created_at            REAL NOT NULL,
    activated_at          REAL,
    updated_at            REAL NOT NULL,
    telegram_confirmed_at REAL,
    last_ingress_at       REAL,
    last_push_ok_at       REAL,
    last_push_error       TEXT,
    ack_at                REAL,
    revoked_at            REAL,
    revoked_reason        TEXT
);
CREATE INDEX IF NOT EXISTS idx_push_reg_owner ON push_registrations(owner_digest, state);
CREATE INDEX IF NOT EXISTS idx_push_reg_state ON push_registrations(state, pairing_expires_at);

CREATE TABLE IF NOT EXISTS push_deliveries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    registration_id TEXT NOT NULL REFERENCES push_registrations(registration_id) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN ('telegram', 'test')),
    test_id         TEXT,
    state           TEXT NOT NULL CHECK (state IN ('queued', 'inflight', 'done', 'failed', 'expired')),
    body            BLOB NOT NULL,
    created_at      REAL NOT NULL,
    expires_at      REAL NOT NULL,
    next_attempt_at REAL NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    lease_until     REAL,
    last_status     INTEGER,
    last_error      TEXT
);
CREATE INDEX IF NOT EXISTS idx_push_deliv_due ON push_deliveries(state, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_push_deliv_reg ON push_deliveries(registration_id, state);

CREATE TABLE IF NOT EXISTS push_counters (
    day    TEXT NOT NULL,
    metric TEXT NOT NULL,
    value  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, metric)
);

CREATE TABLE IF NOT EXISTS rate_events (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL,
    key   TEXT NOT NULL,
    at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_push_rate_lookup ON rate_events(scope, key, at);

CREATE TABLE IF NOT EXISTS kv (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at REAL NOT NULL
);
"""

PUSH_MIGRATIONS: tuple[tuple[int, str], ...] = ((1, _DDL_V1),)
