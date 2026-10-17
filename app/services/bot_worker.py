"""Бот-воркер: приём /report <nonce> и подтверждение владения аккаунтом.

Поток:
1. long polling getUpdates;
2. для каждого сообщения берём message.from.id (не доверяем никаким другим id);
3. проверяем, что отправитель — не бот и находится в allowlist;
4. применяем лимиты запросов /report (по пользователю и глобальный);
5. валидируем формат nonce, регистрируем хэш как ISSUED с TTL;
6. отвечаем пользователю подтверждением с correlation id (это и есть сигнал
   приложению, что можно переходить к загрузке отчёта).

Важно: регистрация и подтверждение происходят ДО любых сообщений об отказе,
а отказ не раскрывает, находится ли id в списке.
"""

from __future__ import annotations

import contextlib
import logging
import re

from ..config import Settings
from ..db import Database
from ..repository import allowlist, audit, nonces, rate_limit
from ..security import NonceFormatError, hash_nonce, validate_nonce
from ..telegram import (
    ReportBotClient,
    TelegramError,
    TelegramPermanentError,
    TelegramTemporaryError,
    TelegramUpdate,
)
from .settings_service import intake_enabled

log = logging.getLogger(__name__)

_COMMAND_RE = re.compile(r"^/(?P<cmd>[A-Za-z0-9_]+)(?:@(?P<bot>[A-Za-z0-9_]+))?(?:\s+(?P<rest>.*))?$", re.DOTALL)

MSG_CONFIRMED = (
    "Запрос подтверждён.\n"
    "correlation_id: {correlation_id}\n\n"
    "Вернитесь в BeyGram и нажмите «Отправить отчёт». "
    "Ссылка действует {ttl_minutes} мин."
)
MSG_NEED_NONCE = (
    "Отправьте команду в формате:\n/report <код>\n\n"
    "Код формирует BeyGram в разделе Настройки → Диагностика. "
    "Вручную вводить его не нужно."
)
MSG_BAD_NONCE = "Код имеет неверный формат. Сформируйте новый отчёт в BeyGram и попробуйте снова."
MSG_RATE_LIMITED = "Слишком много запросов подтверждения. Попробуйте позже."
MSG_DISABLED = "Приём отчётов временно приостановлен. Попробуйте позже."
MSG_NOT_ALLOWED = (
    "Этот аккаунт не в списке участников беты. "
    "Обратитесь к разработчику BeyGram, чтобы получить доступ."
)


async def run(ctx) -> None:
    """Цикл long polling. Перезапускается при временных сбоях Bot API."""
    import asyncio

    settings: Settings = ctx.settings
    client: ReportBotClient = ctx.report_bot

    offset: int | None = None
    backoff = settings.bot_error_backoff_seconds

    try:
        me = await client.get_me()
        log.info("report bot started", extra={"bot_id": me.get("id"), "username": me.get("username")})
    except TelegramError as exc:
        log.error("cannot reach Bot API at startup: %s", exc.__class__.__name__)

    while not ctx.stopping.is_set():
        try:
            updates = await client.get_updates(
                offset,
                timeout_seconds=settings.bot_poll_timeout_seconds,
                allowed_updates=["message", "edited_message"],
            )
            backoff = settings.bot_error_backoff_seconds
        except TelegramTemporaryError as exc:
            log.warning("getUpdates temporary failure: %s", exc.__class__.__name__)
            await _sleep(ctx, backoff)
            backoff = min(backoff * 2, 120)
            continue
        except TelegramPermanentError as exc:
            # Неверный токен и т.п. — нет смысла крутиться в цикле каждую секунду.
            log.error("getUpdates permanent failure: %s", exc.__class__.__name__)
            await _sleep(ctx, 60)
            continue
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("unexpected error in bot polling")
            await _sleep(ctx, backoff)
            backoff = min(backoff * 2, 120)
            continue

        for update in updates:
            offset = max(offset or 0, update.update_id + 1)
            try:
                await _handle_update(ctx, update)
            except Exception:  # noqa: BLE001 - один плохой апдейт не должен ронять цикл
                log.exception("failed to handle update", extra={"update_id": update.update_id})

        if not updates:
            await _sleep(ctx, settings.bot_poll_interval_seconds)


async def _handle_update(ctx, update: TelegramUpdate) -> None:
    # Игнорируем апдейты без отправителя (каналы, служебное) и сообщения от ботов.
    if update.from_id is None or update.from_is_bot:
        return

    # Доверяем только приватному чату: пользователь должен писать боту лично.
    if update.chat_type not in (None, "private"):
        log.info("ignoring non-private message", extra={"chat_type": update.chat_type})
        return

    parsed = _parse_command(update.text)
    if parsed is None:
        return
    command, argument = parsed

    user_id = update.from_id

    if command in {"start", "help"}:
        await _reply(ctx, user_id, update.message_id, MSG_NEED_NONCE)
        return

    if command != "report":
        return

    # --- /report <nonce> ---------------------------------------------------
    if not argument:
        await _reply(ctx, user_id, update.message_id, MSG_NEED_NONCE)
        return

    await _handle_report_command(ctx, user_id=user_id, message_id=update.message_id, nonce=argument)


async def _handle_report_command(ctx, *, user_id: int, message_id: int | None, nonce: str) -> None:
    settings: Settings = ctx.settings
    db: Database = ctx.db

    def _prepare() -> tuple[str, str | None]:
        """Всё под одним локом: лимиты, allowlist, регистрация nonce.

        Возвращает (outcome, correlation_id). outcome ∈
        {confirmed, disabled, not_allowed, rate_limited, bad_nonce, conflict}.
        """
        with db.transaction() as conn:
            if not intake_enabled(conn, settings):
                return "disabled", None

            # Лимиты применяются ДО регистрации, чтобы /report не был вектором спама.
            ok, _ = rate_limit.check_and_record(
                conn,
                scope=rate_limit.SCOPE_USER_REPORT_CMD,
                key=str(user_id),
                limit=settings.rl_user_report_cmd_per_hour,
                window_seconds=3600,
            )
            if not ok:
                audit.write(conn, actor="bot", action="report_cmd_rate_limited", target=str(user_id))
                return "rate_limited", None

            ok, _ = rate_limit.check_and_record(
                conn,
                scope=rate_limit.SCOPE_GLOBAL_REPORT_CMD,
                key=None,
                limit=settings.rl_global_report_cmd_per_hour,
                window_seconds=3600,
            )
            if not ok:
                audit.write(conn, actor="bot", action="report_cmd_global_rate_limited")
                return "rate_limited", None

            # Валидация формата ДО обращения к allowlist: мусор отсекаем рано.
            try:
                validated = validate_nonce(nonce)
            except NonceFormatError:
                return "bad_nonce", None

            if not allowlist.is_active(conn, user_id):
                # Не сообщаем, есть ли id в списке; просто отказ.
                audit.write(conn, actor="bot", action="report_cmd_denied", target=str(user_id))
                return "not_allowed", None

            nonce_hash = hash_nonce(settings.nonce_pepper, validated.raw)
            try:
                record, created = nonces.register_issued(
                    conn,
                    nonce_hash=nonce_hash,
                    telegram_user_id=user_id,
                    ttl_seconds=settings.nonce_ttl_seconds,
                )
            except nonces.NonceConflictError:
                audit.write(
                    conn,
                    actor="bot",
                    action="report_cmd_conflict",
                    target=str(user_id),
                )
                return "conflict", None

            correlation_id = nonce_hash[:16]
            audit.write(
                conn,
                actor="bot",
                action="nonce_issued" if created else "nonce_reissued",
                target=correlation_id,
                detail={"telegram_user_id": user_id},
            )
            return "confirmed", correlation_id

    outcome, correlation_id = await db.run(_prepare)

    messages = {
        "confirmed": MSG_CONFIRMED.format(
            correlation_id=correlation_id or "",
            ttl_minutes=max(1, settings.nonce_ttl_seconds // 60),
        ),
        "disabled": MSG_DISABLED,
        "not_allowed": MSG_NOT_ALLOWED,
        "rate_limited": MSG_RATE_LIMITED,
        "bad_nonce": MSG_BAD_NONCE,
        "conflict": MSG_BAD_NONCE,
    }
    text = messages.get(outcome, MSG_NEED_NONCE)
    # Подтверждение отправляем отдельным сообщением, не скрывая действие.
    await _reply(ctx, user_id, message_id, text)

    log.info(
        "report command handled",
        extra={"outcome": outcome, "telegram_user_id": user_id},
    )


async def _reply(ctx, chat_id: int, reply_to: int | None, text: str) -> None:
    try:
        await ctx.report_bot.send_message(chat_id, text, reply_to_message_id=reply_to)
    except TelegramError as exc:
        # Пользователь мог заблокировать бота — это нормальная ситуация, не ошибка сервера.
        log.warning("cannot reply to user: %s", exc.__class__.__name__)


def _parse_command(text: str) -> tuple[str, str] | None:
    """Разбирает '/report@Bot nonce' → ('report', 'nonce')."""
    text = (text or "").strip()
    if not text.startswith("/"):
        return None
    match = _COMMAND_RE.match(text)
    if not match:
        return None
    command = match.group("cmd").lower()
    rest = (match.group("rest") or "").strip()
    # nonce — единственный аргумент; лишние токены не поддерживаем.
    argument = rest.split()[0] if rest else ""
    return command, argument


async def _sleep(ctx, seconds: float) -> None:
    import asyncio

    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(ctx.stopping.wait(), timeout=seconds)
