"""Тесты бот-воркера: подтверждение nonce, allowlist, лимиты, разбор команд."""

from __future__ import annotations

import pytest

from app.repository import allowlist, nonces
from app.security import hash_nonce
from app.services import bot_worker
from app.telegram import TelegramUpdate


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


@pytest.fixture()
def ctx(db, settings):
    return FakeCtx(db, settings, FakeBotClient())


def _update(user_id: int, text: str, *, is_bot: bool = False, chat_type: str = "private") -> TelegramUpdate:
    return TelegramUpdate(
        update_id=1,
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
