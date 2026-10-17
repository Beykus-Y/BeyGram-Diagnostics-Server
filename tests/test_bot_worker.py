"""Тесты бот-воркера: подтверждение nonce, allowlist, лимиты, разбор команд."""

from __future__ import annotations

import itertools

import pytest

from app.repository import allowlist, nonces
from app.security import hash_nonce
from app.services import bot_worker
from app.telegram import TelegramUpdate

_update_ids = itertools.count(1)


class FakeBotClient:
    """Подменяет ReportBotClient: записывает ответы, ничего не отправляет."""

    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.has_token = True

    async def send_message(self, chat_id, text, *, reply_to_message_id=None, disable_notification=False):
        self.sent.append({"chat_id": chat_id, "text": text, "reply_to": reply_to_message_id})
        return {"message_id": len(self.sent)}


class FakeCtx:
    def __init__(self, db, settings, bot) -> None:
        self.db = db
        self.settings = settings
        self.report_bot = bot

    @property
    def stopping(self):
        import asyncio

        return asyncio.Event()

    def worker_success(self, name: str) -> None:  # noqa: ARG002
        pass

    def worker_failure(self, name: str, error: str) -> None:  # noqa: ARG002
        pass


@pytest.fixture()
def ctx(db, settings):
    return FakeCtx(db, settings, FakeBotClient())


def _update(
    user_id: int,
    text: str,
    *,
    is_bot: bool = False,
    chat_type: str = "private",
    update_id: int | None = None,
) -> TelegramUpdate:
    return TelegramUpdate(
        update_id=update_id if update_id is not None else next(_update_ids),
        message_id=10,
        chat_id=user_id,
        chat_type=chat_type,
        from_id=user_id,
        from_is_bot=is_bot,
        text=text,
    )


def _allow(db, user_id: int) -> None:
    with db.transaction() as conn:
        allowlist.add(conn, user_id)


def _nonce_state(db, settings, nonce: str):
    with db.transaction() as conn:
        return nonces.get(conn, hash_nonce(settings.nonce_pepper, nonce))


async def test_valid_report_command_issues_nonce(ctx, db, settings):
    from app.security import generate_nonce

    _allow(db, 700001)
    nonce = generate_nonce()

    await bot_worker._handle_update(ctx, _update(700001, f"/report {nonce}"))

    record = _nonce_state(db, settings, nonce)
    assert record is not None
    assert record.state == "ISSUED"
    assert record.telegram_user_id == 700001
    assert ctx.report_bot.sent, "пользователь должен получить подтверждение"
    assert "correlation_id" in ctx.report_bot.sent[-1]["text"]


async def test_report_command_with_bot_suffix(ctx, db, settings):
    from app.security import generate_nonce

    _allow(db, 700002)
    nonce = generate_nonce()
    await bot_worker._handle_update(ctx, _update(700002, f"/report@fake_report_bot {nonce}"))

    assert _nonce_state(db, settings, nonce) is not None


async def test_user_not_in_allowlist_gets_no_nonce(ctx, db, settings):
    from app.security import generate_nonce

    nonce = generate_nonce()
    await bot_worker._handle_update(ctx, _update(700003, f"/report {nonce}"))

    assert _nonce_state(db, settings, nonce) is None
    assert "беты" in ctx.report_bot.sent[-1]["text"]


async def test_malformed_nonce_rejected(ctx, db, settings):
    _allow(db, 700004)
    await bot_worker._handle_update(ctx, _update(700004, "/report not-valid"))

    with db.transaction() as conn:
        assert nonces.count_by_state(conn) == {}
    assert "формат" in ctx.report_bot.sent[-1]["text"]


async def test_messages_from_bots_ignored(ctx, db, settings):
    from app.security import generate_nonce

    _allow(db, 700005)
    nonce = generate_nonce()
    await bot_worker._handle_update(ctx, _update(700005, f"/report {nonce}", is_bot=True))

    assert _nonce_state(db, settings, nonce) is None


async def test_group_chat_ignored(ctx, db, settings):
    from app.security import generate_nonce

    _allow(db, 700006)
    nonce = generate_nonce()
    await bot_worker._handle_update(
        ctx, _update(700006, f"/report {nonce}", chat_type="supergroup")
    )

    assert _nonce_state(db, settings, nonce) is None


async def test_start_command_returns_instructions(ctx):
    await bot_worker._handle_update(ctx, _update(700007, "/start"))
    assert "/report" in ctx.report_bot.sent[-1]["text"]


async def test_report_without_nonce_returns_instructions(ctx, db, settings):
    _allow(db, 700008)
    await bot_worker._handle_update(ctx, _update(700008, "/report"))
    assert "/report" in ctx.report_bot.sent[-1]["text"]


async def test_report_command_rate_limit(ctx, db, settings):
    _allow(db, 700009)
    settings.rl_user_report_cmd_per_hour = 2

    from app.security import generate_nonce

    for _ in range(2):
        await bot_worker._handle_update(ctx, _update(700009, f"/report {generate_nonce()}"))

    await bot_worker._handle_update(ctx, _update(700009, f"/report {generate_nonce()}"))
    assert "Слишком много" in ctx.report_bot.sent[-1]["text"]

    with db.transaction() as conn:
        assert nonces.count_by_state(conn).get("ISSUED", 0) == 2


async def test_intake_disabled_blocks_nonce(ctx, db, settings):
    from app.repository import kv
    from app.security import generate_nonce

    _allow(db, 700010)
    with db.transaction() as conn:
        kv.set_value(conn, kv.KEY_ACCEPT_REPORTS, "false")

    nonce = generate_nonce()
    await bot_worker._handle_update(ctx, _update(700010, f"/report {nonce}"))

    assert _nonce_state(db, settings, nonce) is None
    assert "приостановлен" in ctx.report_bot.sent[-1]["text"]


async def test_duplicate_update_does_not_spend_rate_limit(ctx, db, settings):
    """Повторная доставка апдейта (сбой после обработки) не тратит лимит."""
    from app.security import generate_nonce

    _allow(db, 700011)
    settings.rl_user_report_cmd_per_hour = 1

    nonce = generate_nonce()
    update = _update(700011, f"/report {nonce}", update_id=100)
    await bot_worker._handle_update(ctx, update)
    assert _nonce_state(db, settings, nonce) is not None
    replies_after_first = len(ctx.report_bot.sent)

    # Тот же update_id приходит снова (например, после падения процесса).
    await bot_worker._handle_update(ctx, _update(700011, f"/report {nonce}", update_id=100))

    assert len(ctx.report_bot.sent) == replies_after_first, "дубль не должен отвечать"
    with db.transaction() as conn:
        assert nonces.count_by_state(conn).get("ISSUED", 0) == 1


async def test_offset_survives_restart(ctx, db, settings):
    """Offset хранится в kv и восстанавливается после «рестарта»."""
    await bot_worker._commit_offset(ctx, 41)
    assert await bot_worker._load_offset_db(ctx) == 42


async def test_commit_offset_only_moves_forward(ctx, db, settings):
    await bot_worker._commit_offset(ctx, 10)
    await bot_worker._commit_offset(ctx, 5)
    assert await bot_worker._load_offset_db(ctx) == 11


class FlakyBot(FakeBotClient):
    """Первые N вызовов send_message падают временной ошибкой Bot API."""

    def __init__(self, fail_times: int) -> None:
        super().__init__()
        self.fail_times = fail_times

    async def send_message(self, chat_id, text, *, reply_to_message_id=None, disable_notification=False):
        if self.fail_times > 0:
            self.fail_times -= 1
            from app.telegram import TelegramTemporaryError

            raise TelegramTemporaryError("upstream 502")
        return await super().send_message(
            chat_id, text, reply_to_message_id=reply_to_message_id, disable_notification=disable_notification
        )


class BlockedBot(FakeBotClient):
    """Пользователь заблокировал бота — постоянная ошибка."""

    async def send_message(self, chat_id, text, *, reply_to_message_id=None, disable_notification=False):
        from app.telegram import TelegramPermanentError

        raise TelegramPermanentError("bot was blocked by the user")


async def test_confirmation_retried_before_offset_commit(ctx, db, settings, monkeypatch):
    """Временный сбой Bot API не теряет подтверждение: ретрай до коммита offset."""
    from app.repository import kv
    from app.security import generate_nonce

    monkeypatch.setattr(bot_worker, "_REPLY_BACKOFF_SECONDS", (0.0, 0.0, 0.0))
    flaky = FlakyBot(fail_times=1)
    flaky_ctx = FakeCtx(db, settings, flaky)

    _allow(db, 700012)
    nonce = generate_nonce()
    await bot_worker._handle_report_command(
        flaky_ctx, user_id=700012, message_id=10, nonce=nonce, update_id=500
    )

    # Подтверждение доставлено со второй попытки.
    assert len(flaky.sent) == 1
    # И только после этого апдейт отмечен обработанным.
    with db.transaction() as conn:
        stored = kv.get_value(conn, kv.KEY_BOT_LAST_UPDATE)
    assert stored == "500"
    assert _nonce_state(db, settings, nonce) is not None


async def test_permanent_reply_failure_still_commits(ctx, db, settings):
    """Если пользователь заблокировал бота, не зацикливаемся: nonce выдан."""
    from app.repository import kv
    from app.security import generate_nonce

    blocked_ctx = FakeCtx(db, settings, BlockedBot())

    _allow(db, 700013)
    nonce = generate_nonce()
    await bot_worker._handle_report_command(
        blocked_ctx, user_id=700013, message_id=10, nonce=nonce, update_id=600
    )

    with db.transaction() as conn:
        stored = kv.get_value(conn, kv.KEY_BOT_LAST_UPDATE)
    assert stored == "600", "апдейт не должен вечно переобрабатываться"
    assert _nonce_state(db, settings, nonce) is not None


async def test_reissue_does_not_spend_rate_limit(ctx, db, settings):
    """Повторный /report с тем же nonce — reissue без повторного списания."""
    from app.security import generate_nonce

    _allow(db, 700014)
    settings.rl_user_report_cmd_per_hour = 1

    nonce = generate_nonce()
    await bot_worker._handle_report_command(
        ctx, user_id=700014, message_id=10, nonce=nonce, update_id=701
    )
    # Тот же nonce, новый апдейт: лимит исчерпан, но reissue проходит.
    await bot_worker._handle_report_command(
        ctx, user_id=700014, message_id=11, nonce=nonce, update_id=702
    )

    assert _nonce_state(db, settings, nonce) is not None
    confirmed_replies = [s for s in ctx.report_bot.sent if "correlation_id" in s["text"]]
    assert len(confirmed_replies) == 2, "оба раза пользователь получил подтверждение"


class AlwaysFailsBot(FakeBotClient):
    """Постоянные временные сбои Bot API (упавший Telegram)."""

    async def send_message(self, chat_id, text, *, reply_to_message_id=None, disable_notification=False):
        from app.telegram import TelegramTemporaryError

        raise TelegramTemporaryError("upstream 502")


async def test_reply_failure_leaves_update_unacknowledged(ctx, db, settings, monkeypatch):
    """Временный сбой: апдейт НЕ фиксируется — ответ будет отправлен снова."""
    from app.repository import kv
    from app.security import generate_nonce

    monkeypatch.setattr(bot_worker, "_REPLY_BACKOFF_SECONDS", (0.0, 0.0, 0.0))
    failing_ctx = FakeCtx(db, settings, AlwaysFailsBot())

    _allow(db, 700015)
    nonce = generate_nonce()
    processed = await bot_worker._handle_report_command(
        failing_ctx, user_id=700015, message_id=10, nonce=nonce, update_id=800
    )

    assert processed is False, "при недоставленном подтверждении апдейт не фиксируется"
    with db.transaction() as conn:
        assert kv.get_value(conn, kv.KEY_BOT_LAST_UPDATE) is None


async def test_reply_recovered_when_telegram_returns(ctx, db, settings, monkeypatch):
    """После восстановления Bot API подтверждение доставляется автоматически.

    Апдейт переобрабатывается (offset не был зафиксирован), лимит НЕ тратится
    повторно (reissue), пользователь получает подтверждение.
    """
    from app.repository import kv
    from app.security import generate_nonce

    monkeypatch.setattr(bot_worker, "_REPLY_BACKOFF_SECONDS", (0.0, 0.0, 0.0))
    _allow(db, 700016)
    settings.rl_user_report_cmd_per_hour = 1

    nonce = generate_nonce()
    # Шаг 1: Telegram лежит — подтверждение не ушло, апдейт не зафиксирован.
    down_ctx = FakeCtx(db, settings, AlwaysFailsBot())
    processed = await bot_worker._handle_report_command(
        down_ctx, user_id=700016, message_id=10, nonce=nonce, update_id=900
    )
    assert processed is False

    # Шаг 2: Telegram восстановился — тот же апдейт обрабатывается заново.
    recovered_ctx = FakeCtx(db, settings, FakeBotClient())
    processed = await bot_worker._handle_report_command(
        recovered_ctx, user_id=700016, message_id=10, nonce=nonce, update_id=900
    )
    assert processed is True
    assert len(recovered_ctx.report_bot.sent) == 1, "подтверждение доставлено"
    assert "correlation_id" in recovered_ctx.report_bot.sent[0]["text"]

    with db.transaction() as conn:
        assert kv.get_value(conn, kv.KEY_BOT_LAST_UPDATE) == "900"


async def test_expired_nonce_not_reconfirmed(ctx, db, settings):
    """Просроченный (но ещё ISSUED до maintenance) nonce не подтверждается (#17)."""
    from app.security import generate_nonce

    _allow(db, 700017)
    nonce = generate_nonce()
    # Первая выдача — валидна.
    await bot_worker._handle_report_command(
        ctx, user_id=700017, message_id=10, nonce=nonce, update_id=910
    )

    # Симулируем прошедший TTL без ожидания maintenance.
    with db.transaction() as conn:
        conn.execute("UPDATE nonces SET expires_at = 1 WHERE telegram_user_id = 700017")

    sent_before = len(ctx.report_bot.sent)
    processed = await bot_worker._handle_report_command(
        ctx, user_id=700017, message_id=11, nonce=nonce, update_id=911
    )

    # Пользователь НЕ получает нового «Запрос подтверждён».
    assert processed is True
    new_replies = ctx.report_bot.sent[sent_before:]
    assert not any("correlation_id" in s["text"] for s in new_replies), (
        "просроченный nonce нельзя подтверждать заново"
    )
    # Ответ об отказе приходит (nonce уже бесполезен — цикл перезапуска завершён).
    assert any("неверный формат" in s["text"] for s in new_replies)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("/report abc", ("report", "abc")),
        ("/report@mybot abc", ("report", "abc")),
        ("/start", ("start", "")),
        ("not a command", None),
        ("", None),
    ],
)
def test_parse_command(text, expected):
    assert bot_worker._parse_command(text) == expected
