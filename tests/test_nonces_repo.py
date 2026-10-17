"""Тесты репозитория nonce: атомарный claim, состояния, TTL."""

from __future__ import annotations

import pytest

from app.repository import nonces
from app.state import NONCE_ACCEPTED, NONCE_DELIVERED, NONCE_EXPIRED, NONCE_ISSUED, NONCE_PROCESSING


def _hash(n: int) -> str:
    return f"{n:064d}"


def test_register_and_claim_flow(db):
    with db.transaction() as conn:
        record, created = nonces.register_issued(
            conn, nonce_hash=_hash(1), telegram_user_id=100, ttl_seconds=300
        )
        assert created is True
        assert record.state == NONCE_ISSUED

        claimed = nonces.claim(
            conn,
            nonce_hash=_hash(1),
            telegram_user_id=100,
            report_id="123e4567-e89b-42d3-a456-426614174000",
            request_fingerprint="fp1",
        )
        assert claimed is not None
        assert claimed.state == NONCE_PROCESSING
        assert claimed.report_id == "123e4567-e89b-42d3-a456-426614174000"


def test_claim_is_single_use(db):
    with db.transaction() as conn:
        nonces.register_issued(conn, nonce_hash=_hash(2), telegram_user_id=100, ttl_seconds=300)
        first = nonces.claim(
            conn,
            nonce_hash=_hash(2),
            telegram_user_id=100,
            report_id="123e4567-e89b-42d3-a456-426614174000",
            request_fingerprint="fp",
        )
        assert first is not None

        # Повторный claim тем же nonce невозможен — это и есть защита от дублей.
        second = nonces.claim(
            conn,
            nonce_hash=_hash(2),
            telegram_user_id=100,
            report_id="123e4567-e89b-42d3-a456-426614174001",
            request_fingerprint="fp",
        )
        assert second is None


def test_claim_rejects_other_user(db):
    with db.transaction() as conn:
        nonces.register_issued(conn, nonce_hash=_hash(3), telegram_user_id=100, ttl_seconds=300)
        stolen = nonces.claim(
            conn,
            nonce_hash=_hash(3),
            telegram_user_id=999,
            report_id="123e4567-e89b-42d3-a456-426614174000",
            request_fingerprint="fp",
        )
        assert stolen is None


def test_claim_rejects_expired(db):
    with db.transaction() as conn:
        nonces.register_issued(
            conn, nonce_hash=_hash(4), telegram_user_id=100, ttl_seconds=300, at=1000.0
        )
        late = nonces.claim(
            conn,
            nonce_hash=_hash(4),
            telegram_user_id=100,
            report_id="123e4567-e89b-42d3-a456-426614174000",
            request_fingerprint="fp",
            at=1000.0 + 301,
        )
        assert late is None


def test_reissue_same_nonce_is_idempotent(db):
    with db.transaction() as conn:
        _, created_first = nonces.register_issued(
            conn, nonce_hash=_hash(5), telegram_user_id=100, ttl_seconds=300
        )
        _, created_second = nonces.register_issued(
            conn, nonce_hash=_hash(5), telegram_user_id=100, ttl_seconds=300
        )
        assert created_first is True
        assert created_second is False


def test_expired_issued_nonce_is_not_usable(db):
    """ISSUED с прошедшим TTL: is_live остаётся True, is_usable — False (#17)."""
    with db.transaction() as conn:
        nonces.register_issued(
            conn, nonce_hash=_hash(50), telegram_user_id=100, ttl_seconds=60, at=1000.0
        )
        record = nonces.get(conn, _hash(50))
        assert record.is_live is True
        assert record.is_usable(at=1000.0 + 30) is True
        assert record.is_usable(at=1000.0 + 61) is False

        # Повторная регистрация просроченного nonce отклоняется, даже если
        # maintenance ещё не пометил его EXPIRED.
        with pytest.raises(nonces.NonceConflictError):
            nonces.register_issued(
                conn, nonce_hash=_hash(50), telegram_user_id=100, ttl_seconds=300, at=1000.0 + 61
            )


def test_reuse_after_consumption_rejected(db):
    with db.transaction() as conn:
        nonces.register_issued(conn, nonce_hash=_hash(6), telegram_user_id=100, ttl_seconds=300)
        nonces.claim(
            conn,
            nonce_hash=_hash(6),
            telegram_user_id=100,
            report_id="123e4567-e89b-42d3-a456-426614174000",
            request_fingerprint="fp",
        )
        nonces.mark_delivered(conn, _hash(6))

        with pytest.raises(nonces.NonceConflictError):
            nonces.register_issued(
                conn, nonce_hash=_hash(6), telegram_user_id=100, ttl_seconds=300
            )


def test_expire_stale_marks_expired(db):
    with db.transaction() as conn:
        nonces.register_issued(
            conn, nonce_hash=_hash(7), telegram_user_id=100, ttl_seconds=60, at=1000.0
        )
        changed = nonces.expire_stale(conn, at=1000.0 + 61)
        assert changed == 1
        record = nonces.get(conn, _hash(7))
        assert record is not None and record.state == NONCE_EXPIRED


def test_revoke_for_user(db):
    with db.transaction() as conn:
        nonces.register_issued(conn, nonce_hash=_hash(8), telegram_user_id=100, ttl_seconds=300)
        nonces.register_issued(conn, nonce_hash=_hash(9), telegram_user_id=200, ttl_seconds=300)
        revoked = nonces.revoke_for_user(conn, 100)
        assert revoked == 1
        assert nonces.get(conn, _hash(8)).state == "REVOKED"
        assert nonces.get(conn, _hash(9)).state == NONCE_ISSUED


def test_mark_accepted_and_delivered(db):
    with db.transaction() as conn:
        nonces.register_issued(conn, nonce_hash=_hash(10), telegram_user_id=100, ttl_seconds=300)
        nonces.claim(
            conn,
            nonce_hash=_hash(10),
            telegram_user_id=100,
            report_id="123e4567-e89b-42d3-a456-426614174000",
            request_fingerprint="fp",
        )
        nonces.mark_accepted(conn, _hash(10))
        assert nonces.get(conn, _hash(10)).state == NONCE_ACCEPTED
        nonces.mark_delivered(conn, _hash(10))
        record = nonces.get(conn, _hash(10))
        assert record.state == NONCE_DELIVERED
        assert record.delivered_at is not None
