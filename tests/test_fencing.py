"""Тесты fencing (claim_version), возобновляемой доставки и чанкинга.

Покрывают issues #2/#3/#4: воркер не может перезаписать отозванный отчёт,
ретрай продолжает с подтверждённой части, длинные отчёты не теряют данные.
"""

from __future__ import annotations

import uuid

from app.repository import allowlist, nonces, reports
from app.services import delivery_worker
from app.services.formatting import MAX_MESSAGE_CHARS, build_report_message
from app.state import REPORT_DROPPED, REPORT_QUEUED
from tests.test_delivery_worker import FakeCtx, FakeDeliveryBot, _seed_report


def _drop(db, user_id: int) -> None:
    with db.transaction() as conn:
        reports.drop_pending_for_user(conn, user_id, reason="allowlist revoked")


# --- Repository-level fencing -------------------------------------------------


def test_fenced_worker_cannot_mark_dropped_as_delivered(db, settings):
    report_id = _seed_report(db, settings)

    with db.transaction() as conn:
        claimed = reports.claim_next_for_delivery(conn, lease_seconds=180)
        assert claimed is not None
        version = claimed.claim_version
        user_id = claimed.telegram_user_id

    _drop(db, user_id)

    with db.transaction() as conn:
        # «Старый» воркер пытается записать доставку со своим claim_version.
        assert (
            reports.mark_delivered(conn, report_id, claim_version=version, message_id=1) is False
        )
        assert reports.get(conn, report_id).status == REPORT_DROPPED


def test_fenced_worker_cannot_requeue_dropped_report(db, settings):
    report_id = _seed_report(db, settings)

    with db.transaction() as conn:
        claimed = reports.claim_next_for_delivery(conn, lease_seconds=180)
        version = claimed.claim_version
        user_id = claimed.telegram_user_id

    _drop(db, user_id)

    with db.transaction() as conn:
        new_state = reports.schedule_retry(
            conn,
            report_id,
            claim_version=version,
            error="temporary: upstream 502",
            delay_seconds=15,
        )
        assert new_state == REPORT_DROPPED, "fenced ретрай не должен поднимать DROPPED"
        assert reports.get(conn, report_id).status == REPORT_DROPPED


def test_fenced_progress_rejected(db, settings):
    report_id = _seed_report(db, settings)

    with db.transaction() as conn:
        claimed = reports.claim_next_for_delivery(conn, lease_seconds=180)
        version = claimed.claim_version

        assert (
            reports.save_delivery_progress(
                conn, report_id, claim_version=version + 1, parts_delivered=1, message_id=None
            )
            is False
        )
        assert (
            reports.save_delivery_progress(
                conn, report_id, claim_version=version, parts_delivered=1, message_id=10
            )
            is True
        )
        # Прогресс не откатывается назад.
        assert (
            reports.save_delivery_progress(
                conn, report_id, claim_version=version, parts_delivered=1, message_id=11
            )
            is False
        )


def test_expired_lease_reclaim_increments_claim_version(db, settings):
    _seed_report(db, settings)

    with db.transaction() as conn:
        first = reports.claim_next_for_delivery(conn, lease_seconds=180)
        # lease истёк, отчёт вернулся в очередь и был взят заново.
        conn.execute(
            "UPDATE reports SET status='QUEUED', lease_until=NULL WHERE report_id=?",
            (first.report_id,),
        )
        second = reports.claim_next_for_delivery(conn, lease_seconds=180)

    assert second.claim_version == first.claim_version + 1


# --- Доставка: отзыв между частями и докачка ----------------------------------


class DroppingBot(FakeDeliveryBot):
    """Отзывает отчёт после первой отправленной части (симуляция админ-действия)."""

    def __init__(self, db, user_id: int) -> None:
        super().__init__()
        self._db = db
        self._user_id = user_id

    async def send_message(self, chat_id, text, *, parse_mode=None, disable_notification=False):
        result = await super().send_message(
            chat_id, text, parse_mode=parse_mode, disable_notification=disable_notification
        )
        _drop(self._db, self._user_id)
        return result


def _seed_long_report(db, settings, *, user_id: int = 900002) -> str:
    """Отчёт с большим описанием — гарантирует несколько частей."""
    with db.transaction() as conn:
        from app.security import hash_nonce

        report_id = str(uuid.uuid4())
        nonce_hash = hash_nonce(settings.nonce_pepper, "B" * 43)
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
            description="строка диагностики\n" * 400,
            summary=None,
            events=[],
            client_meta=None,
            payload_fingerprint="fp",
            body_bytes=100,
            app_version=None,
            max_attempts=settings.worker_max_attempts,
            retention_days=30,
        )
        nonces.mark_accepted(conn, nonce_hash)
    return report_id


async def test_report_dropped_mid_delivery_stays_dropped(db, settings):
    report_id = _seed_long_report(db, settings)
    bot = DroppingBot(db, 900002)
    ctx = FakeCtx(db, settings, bot)

    processed = await delivery_worker._process_one(ctx)
    assert processed is True

    with db.transaction() as conn:
        record = reports.get(conn, report_id)
        assert record.status == REPORT_DROPPED, "отозванный отчёт не должен стать DELIVERED"

    parts_sent = len(bot.calls)
    assert parts_sent < len(build_report_message(_get_record(db, report_id))), (
        "после отзыва оставшиеся части отправляться не должны"
    )


async def test_retry_resumes_from_confirmed_part(db, settings):
    """После сбоя на 2-й части ретрай не отправляет 1-ю часть повторно."""
    report_id = _seed_long_report(db, settings)
    bot = FailAfterFirstBot()
    ctx = FakeCtx(db, settings, bot)

    # Попытка 1: первая часть уходит, на второй — временный сбой.
    await delivery_worker._process_one(ctx)
    with db.transaction() as conn:
        record = reports.get(conn, report_id)
        assert record.status == REPORT_QUEUED
        assert record.delivered_parts == 1, "прогресс первой части должен сохраниться"
        conn.execute("UPDATE reports SET next_attempt_at = 0 WHERE report_id = ?", (report_id,))

    # Попытка 2: продолжение со 2-й части.
    first_call_count = len(bot.calls)
    await delivery_worker._process_one(ctx)

    with db.transaction() as conn:
        record = reports.get(conn, report_id)
        assert record.status == "DELIVERED"
        assert record.delivered_parts == len(build_report_message(record))

    resumed_texts = [call["text"] for call in bot.calls[first_call_count:]]
    assert resumed_texts, "ретрай должен отправить оставшиеся части"
    assert all("часть 1/" not in text for text in resumed_texts), (
        "уже доставленная часть не должна отправляться повторно"
    )


class FailAfterFirstBot(FakeDeliveryBot):
    """Первая отправка успешна, вторая — временный сбой, дальше — успех."""

    async def send_message(self, chat_id, text, *, parse_mode=None, disable_notification=False):
        if len(self.calls) == 1:
            self.calls.append({"chat_id": chat_id, "text": text})
            from app.telegram import TelegramTemporaryError

            raise TelegramTemporaryError("upstream 502")
        return await super().send_message(
            chat_id, text, parse_mode=parse_mode, disable_notification=disable_notification
        )


def _get_record(db, report_id: str):
    with db.transaction() as conn:
        return reports.get(conn, report_id)


# --- Чанкинг (#2) ---------------------------------------------------------------


def test_chunks_never_exceed_limit(db, settings):
    """Максимально большой отчёт не теряет данные и не превышает лимит Telegram."""
    report_id = _seed_report(db, settings)
    with db.transaction() as conn:
        conn.execute(
            "UPDATE reports SET description = ?, summary = ? WHERE report_id = ?",
            ("х" * 2000, "с" * 8000, report_id),
        )

    record = _get_record(db, report_id)
    chunks = build_report_message(record)

    assert len(chunks) >= 3
    for chunk in chunks:
        assert len(chunk) <= 4096, "часть должна укладываться в лимит Telegram"
        assert record.report_id in chunk, "каждая часть содержит report_id"
        assert "часть" in chunk, "каждая часть помечена номером"

    # Ничего не потеряно: все символы контента сохранены (разбивка не удаляет).
    restored = "\n".join(chunk.rsplit("\n— часть", 1)[0] for chunk in chunks)
    assert restored.count("х") >= 2000
    assert restored.count("с") >= 8000


def test_chunks_never_exceed_limit_for_single_lines(db, settings):
    """Даже одиночные сверхдлинные строки режутся явно, без превышения лимита."""
    report_id = _seed_report(db, settings)
    with db.transaction() as conn:
        conn.execute(
            "UPDATE reports SET description = ? WHERE report_id = ?",
            ("д" * 12000, report_id),
        )

    record = _get_record(db, report_id)
    chunks = build_report_message(record)
    assert all(len(chunk) <= 4096 for chunk in chunks)
    assert sum(chunk.count("д") for chunk in chunks) >= 12000 - 8  # маркеры «…»


def test_capacity_reserve_leaves_room_for_suffix():
    assert MAX_MESSAGE_CHARS + 120 <= 4096
