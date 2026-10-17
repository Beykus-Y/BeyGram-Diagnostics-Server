"""Клиенты Telegram Bot API.

Два независимых клиента:
* ReportBotClient — читает подтверждения /report <nonce> (long polling);
* DeliveryBotClient — отправляет готовые отчёты разработчику.

Токен бота живёт только здесь, никогда не логируется и не попадает в тело
ответов API. Все обращения — по HTTPS (в dev допускается http для фейкового
Bot API, заданного через TELEGRAM_API_BASE).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

log = logging.getLogger(__name__)


class TelegramError(Exception):
    """Базовая ошибка Bot API."""

    def __init__(self, message: str, *, retryable: bool = False, status: int | None = None) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.status = status


class TelegramTemporaryError(TelegramError):
    """Временный сбой сети/5xx/429 — имеет смысл повторить."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message, retryable=True)
        self.retry_after = retry_after


class TelegramPermanentError(TelegramError):
    """Постоянная ошибка (неверный токен, заблокированный бот, битый чат)."""


@dataclass
class TelegramUpdate:
    """Разобранный апдейт message(в т.ч. edited) без лишних полей."""

    update_id: int
    message_id: int | None
    chat_id: int | None
    chat_type: str | None
    from_id: int | None
    from_is_bot: bool
    text: str
    raw: dict[str, Any] = field(default_factory=dict)


def _parse_update(update: dict[str, Any]) -> TelegramUpdate | None:
    update_id = update.get("update_id")
    if not isinstance(update_id, int):
        return None

    message = (
        update.get("message")
        or update.get("edited_message")
        or update.get("channel_post")
        or {}
    )
    if not isinstance(message, dict) or not message:
        return None

    chat = message.get("chat") or {}
    sender = message.get("from") or {}

    text = message.get("text") or message.get("caption") or ""
    return TelegramUpdate(
        update_id=update_id,
        message_id=message.get("message_id"),
        chat_id=chat.get("id"),
        chat_type=chat.get("type"),
        from_id=sender.get("id"),
        from_is_bot=bool(sender.get("is_bot", False)),
        text=text if isinstance(text, str) else "",
        raw=update,
    )


class _BaseTelegramClient:
    def __init__(self, token: str, api_base: str, *, timeout: float = 30.0) -> None:
        self._token = token
        self._api_base = api_base.rstrip("/")
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    @property
    def has_token(self) -> bool:
        return bool(self._token)

    def _url(self, method: str) -> str:
        return f"{self._api_base}/bot{self._token}/{method}"

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout, follow_redirects=False)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _call(
        self,
        method: str,
        payload: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> Any:
        """Вызывает метод Bot API и возвращает поле result.

        Ошибки классифицируются на временные (retryable) и постоянные, чтобы
        воркер доставки мог безопасно выбирать между ретраем и отказом.
        """
        if not self.has_token:
            raise TelegramPermanentError(f"{method}: bot token is not configured")

        client = await self._ensure_client()
        try:
            response = await client.post(
                self._url(method),
                json=payload or {},
                timeout=timeout if timeout is not None else self._timeout,
            )
        except httpx.TimeoutException as exc:
            raise TelegramTemporaryError(f"{method}: request timed out") from exc
        except httpx.HTTPError as exc:
            raise TelegramTemporaryError(f"{method}: transport error: {exc.__class__.__name__}") from exc

        if response.status_code >= 500:
            raise TelegramTemporaryError(f"{method}: upstream {response.status_code}")

        try:
            data = response.json()
        except ValueError as exc:
            raise TelegramTemporaryError(f"{method}: invalid JSON from Bot API") from exc

        if not data.get("ok"):
            description = str(data.get("description") or "unknown error")
            code = data.get("error_code")
            parameters = data.get("parameters") or {}
            retry_after = parameters.get("retry_after")

            if code == 429:
                raise TelegramTemporaryError(
                    f"{method}: rate limited: {description}",
                    retry_after=float(retry_after) if retry_after else None,
                )
            if isinstance(code, int) and 500 <= code < 600:
                raise TelegramTemporaryError(f"{method}: upstream error {code}: {description}")
            # 400/401/403/404 — постоянные: например, бот заблокирован пользователем,
            # чат не найден, токен недействителен.
            raise TelegramPermanentError(f"{method}: {code}: {description}", status=code)

        return data.get("result")


class ReportBotClient(_BaseTelegramClient):
    """Бот, принимающий /report <nonce> от пользователей BeyGram."""

    async def get_me(self) -> dict[str, Any]:
        result = await self._call("getMe", timeout=10.0)
        return result if isinstance(result, dict) else {}

    async def get_updates(
        self,
        offset: int | None,
        *,
        timeout_seconds: int,
        allowed_updates: list[str] | None = None,
    ) -> list[TelegramUpdate]:
        payload: dict[str, Any] = {
            "timeout": timeout_seconds,
            "allowed_updates": allowed_updates or ["message", "edited_message"],
        }
        if offset is not None:
            payload["offset"] = offset

        result = await self._call("getUpdates", payload, timeout=timeout_seconds + 15)
        if not isinstance(result, list):
            return []
        parsed = [_parse_update(u) for u in result if isinstance(u, dict)]
        return [u for u in parsed if u is not None]

    async def send_message(
        self,
        chat_id: int,
        text: str,
        *,
        reply_to_message_id: int | None = None,
        disable_notification: bool = False,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text[:4096],
            "disable_web_page_preview": True,
            "disable_notification": disable_notification,
        }
        if reply_to_message_id is not None:
            payload["reply_to_message_id"] = reply_to_message_id
        result = await self._call("sendMessage", payload, timeout=15.0)
        return result if isinstance(result, dict) else {}


class DeliveryBotClient(_BaseTelegramClient):
    """Бот, доставляющий готовые отчёты в служебный чат разработчика."""

    async def send_message(
        self,
        chat_id: int,
        text: str,
        *,
        parse_mode: str | None = None,
        disable_notification: bool = False,
    ) -> dict[str, Any]:
        # Telegram ограничивает длину сообщения 4096 символами — разбиение
        # делает delivery-воркер, здесь только защитная обрезка.
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text[:4096],
            "disable_web_page_preview": True,
            "disable_notification": disable_notification,
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        result = await self._call("sendMessage", payload, timeout=20.0)
        return result if isinstance(result, dict) else {}
