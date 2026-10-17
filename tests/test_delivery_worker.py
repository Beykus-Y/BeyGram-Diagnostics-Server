"""Тесты воркера доставки: успех, ретраи, исчерпание попыток, lease."""

from __future__ import annotations

import asyncio

from app.repository import nonces, reports
from app.services import delivery_worker
from app.state import NONCE_DELIVERED, REPORT_DELIVERED, REPORT_FAILED, REPORT_QUEUED
from app.telegram import TelegramPermanentError, TelegramTemporaryError


class FakeDeliveryBot:
    def __init__(self, *, fail_times: int = 0, permanent: bool = False) -> None:
        self.fail_times = fail_times
        self.permanent = permanent
        self.calls: list[dict] = []
        self.has_token = True

    async def send_message(self, chat_id, text, *, parse_mode=None, disable_notification=False):
        self.calls.append({"chat_id": chat_id, "text": text})
        if self.permanent:
            raise TelegramPermanentError("chat not found")
        if self.fail_times > 0:
            self.fail_times -= 1
            raise TelegramTemporaryError("upstream 502")
        return {"message_id": 5000 + len(self.calls)}


class FakeReportBot:
    has_token = False

    async def send_message(self, *args, **kwargs):  # pragma: no cover
        return {}


class FakeCtx:
    def __init__(self, db, settings, delivery_bot) -> None:
        self.db = db
        self.settings = settings
        self.delivery_bot = delivery_bot
        self.report_bot = FakeReportBot()
        self.stopping = asyncio.Event()


def _seed_report(db, settings, *, user_id: int = 900001, report_id: str | None = None) -> str:
    from app.repository import allowlist
    from app.security import hash_nonce

    report_id = report_id or "123e4567-e89b-42d3-a456-426614174000"
    nonce_hash = hash_nonce(settings.nonce_pepper, "A" * 43)

    with db.transaction() as conn:
        allowlist.add(conn, user_id)
        nonces.register_issued(
            conn, nonce_hash=nonce_hash, telegram_user_id=user_id, ttl_seconds=300
        )
        nonces.claim(
            conn,
            nonce_hash=nonce_hash,
            telegram_user_id=user_id,
            report_id=report_id,
            request_fingerprint="fp",
        )
        reports.insert(
            conn,
            report_id=report_id,
            telegram_user_id=user_id,
            nonce_hash=nonce_hash,
            description="Описание проблемы",
            summary=None,
            events=[{"kind": "vpn", "severity": "error", "message": "timeout", "attrs": {}}],
            client_meta={"app_version": "1.0.0"},
            payload_fingerprint="fp",
            body_bytes=100,
            app_version="1.0.0",
            max_attempts=settings.worker_max_attempts,
            retention_days=30,
        )
        nonces.mark_accepted(conn, nonce_hash)
    return report_id


async def test_successful_delivery(db, settings):
    report_id = _seed_report(db, settings)
    bot = FakeDeliveryBot()
    ctx = FakeCtx(db, settings, bot)

    processed = await delivery_worker._process_one(ctx)
    assert processed is True

    with db.transaction() as conn:
        record = reports.get(conn, report_id)
        assert record.status == REPORT_DELIVERED
        assert record.delivered_at is not None
        nonce = nonces.get_by_report_id(conn, report_id)
        assert nonce.state == NONCE_DELIVERED

    assert bot.calls, "должно быть отправлено сообщение в служебный чат"
    assert report_id in bot.calls[0]["text"]


async def test_temporary_failure_schedules_retry(db, settings):
    report_id = _seed_report(db, settings)
    bot = FakeDeliveryBot(fail_times=1)
    ctx = FakeCtx(db, settings, bot)

    await delivery_worker._process_one(ctx)

    with db.transaction() as conn:
        record = reports.get(conn, report_id)
        assert record.status == REPORT_QUEUED
        assert record.attempts == 1
        assert record.next_attempt_at is not None
        assert record.last_error and "temporary" in record.last_error


async def test_permanent_failure_marks_failed(db, settings):
    report_id = _seed_report(db, settings)
    bot = FakeDeliveryBot(permanent=True)
    ctx = FakeCtx(db, settings, bot)

    await delivery_worker._process_one(ctx)

    with db.transaction() as conn:
        record = reports.get(conn, report_id)
        assert record.status == REPORT_FAILED


async def test_exhausted_attempts_marks_failed(db, settings):
    settings.worker_max_attempts = 2
    report_id = _seed_report(db, settings)
    bot = FakeDeliveryBot(fail_times=10)
    ctx = FakeCtx(db, settings, bot)

    await delivery_worker._process_one(ctx)
    # Снимаем задержку, чтобы забрать снова.
    with db.transaction() as conn:
        conn.execute("UPDATE reports SET next_attempt_at = 0 WHERE report_id = ?", (report_id,))

    await delivery_worker._process_one(ctx)

    with db.transaction() as conn:
        record = reports.get(conn, report_id)
        assert record.status == REPORT_FAILED
        assert record.attempts == 2


async def test_no_work_returns_false(db, settings):
    bot = FakeDeliveryBot()
    ctx = FakeCtx(db, settings, bot)
    assert await delivery_worker._process_one(ctx) is False


async def test_expired_lease_requeued(db, settings):
    report_id = _seed_report(db, settings)

    # Эмулируем падение воркера: отчёт в PROCESSING с протухшим lease.
    with db.transaction() as conn:
        conn.execute(
            "UPDATE reports SET status = 'PROCESSING', lease_until = 1, attempts = 1"
            " WHERE report_id = ?",
            (report_id,),
        )

    bot = FakeDeliveryBot()
    ctx = FakeCtx(db, settings, bot)
    await delivery_worker._process_one(ctx)

    with db.transaction() as conn:
        record = reports.get(conn, report_id)
        assert record.status == REPORT_DELIVERED


def test_message_chunking_stays_within_limit(db, settings):
    from app.services.formatting import build_report_message

    report_id = _seed_report(db, settings)
    with db.transaction() as conn:
        reports.get(conn, report_id)
        record = reports.get(conn, report_id)

    chunks = build_report_message(record)
    assert all(len(chunk) <= 4096 for chunk in chunks)
