"""JSON API BG Push (протокол bg-push/1). Подключается под /api/v1/push.

Роли и секреты:
* владелец (нативный клиент BeyGram): Bearer = собственный push-credential (256 бит);
* PWA на устройстве: pairing-секрет (одноразовый, из кода привязки) и затем token;
* Telegram: POST на ingress-URL с capability (256 бит) в пути, без Bearer.

Лимиты, которые должны сохраняться даже при ошибке, пишутся отдельной транзакцией:
иначе неудачные попытки откатывались бы вместе с проверкой и перебор не ограничивался.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from ..context import AppContext
from ..dependencies import client_ip
from ..errors import ERR_NOT_FOUND, ApiError, body_too_large, payload_invalid, rate_limited, unauthorized
from ..push import service
from ..push.crypto import PushCryptoError, aesgcm_envelope
from ..push.runtime import PushRuntime
from ..repository import rate_limit
from ..util import b64url_decode, now

router = APIRouter(prefix="/push", tags=["push"])
log = logging.getLogger(__name__)

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_SECRET_RE = re.compile(r"^Bearer\s+([A-Za-z0-9_-]{43})$", re.IGNORECASE)
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")
_CAPABILITY_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_B64_RE = r"^[A-Za-z0-9_-]+$"
_ENC_AES128GCM = "aes128gcm"
_ENC_AESGCM = "aesgcm"
_SUPPORTED_ENCODINGS = (_ENC_AES128GCM, _ENC_AESGCM)


class _Keys(BaseModel):
    model_config = ConfigDict(extra="forbid")

    p256dh: str = Field(min_length=87, max_length=87, pattern=_B64_RE)
    auth: str = Field(min_length=22, max_length=22, pattern=_B64_RE)


class CompleteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    endpoint: str = Field(min_length=8, max_length=2048)
    keys: _Keys
    ingress: _Keys
    platform: Literal["ios_pwa", "web"] = "ios_pwa"


class AckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    test_id: str = Field(min_length=8, max_length=64, pattern=_B64_RE)


def _runtime(request: Request) -> tuple[AppContext, PushRuntime]:
    ctx: AppContext = request.app.state.context
    if not ctx.settings.enable_push or ctx.push is None or ctx.push_db is None:
        raise ApiError("push_disabled", "BG Push выключен на сервере.", 503)
    return ctx, ctx.push


def _bearer(request: Request) -> str:
    match = _SECRET_RE.match(request.headers.get("authorization", "").strip())
    if not match:
        raise unauthorized()
    token = match.group(1)
    try:
        raw = b64url_decode(token)
    except ValueError:
        raise unauthorized() from None
    if len(raw) != 32:
        raise unauthorized()
    return token


def _check_id(registration_id: str) -> None:
    # Неверный формат неотличим от неизвестной регистрации.
    if not _ID_RE.match(registration_id):
        raise unauthorized()


async def _limit(
    ctx: AppContext,
    *,
    scope: str,
    key: str | None,
    limit: int,
    window_seconds: int,
    message: str,
) -> None:
    """Отдельная транзакция: попытка учитывается, даже если основная операция откатится."""
    at = now()

    def _work() -> None:
        with ctx.push_db.transaction() as conn:  # type: ignore[union-attr]
            ok, delay = rate_limit.check_and_record(
                conn, scope=scope, key=key, limit=limit, window_seconds=window_seconds, at=at
            )
            if not ok:
                raise rate_limited(max(1, int(delay)), message)

    await ctx.push_db.run(_work)  # type: ignore[union-attr]


@router.get("/config")
async def push_config(request: Request) -> dict[str, Any]:
    """Публичные параметры для PWA: ключ VAPID. Секретов здесь нет."""
    ctx: AppContext = request.app.state.context
    if not ctx.settings.enable_push or ctx.push is None:
        return {"enabled": False}
    return {"enabled": True, "protocol": "bg-push/1", "vapid_public_key": ctx.push.vapid.public_key_b64}


@router.post("/registrations", status_code=201)
async def create_registration(request: Request) -> JSONResponse:
    ctx, runtime = _runtime(request)
    owner = _bearer(request)
    settings = ctx.settings
    ip_key = runtime.vault.digest("rate-ip", client_ip(request, settings) or "unknown")
    await _limit(
        ctx,
        scope="push_create_owner",
        key=runtime.vault.digest("rate-owner", owner),
        limit=settings.rl_push_create_owner_per_day,
        window_seconds=86400,
        message="Слишком много попыток привязки. Попробуйте позже.",
    )
    await _limit(
        ctx,
        scope="push_create_ip",
        key=ip_key,
        limit=settings.rl_push_create_ip_per_day,
        window_seconds=86400,
        message="Слишком много попыток привязки. Попробуйте позже.",
    )
    at = now()

    def _work() -> dict[str, Any]:
        with ctx.push_db.transaction() as conn:  # type: ignore[union-attr]
            return service.create_pending(conn, settings=settings, vault=runtime.vault, owner_bearer=owner, at=at)

    created = await ctx.push_db.run(_work)  # type: ignore[union-attr]
    code = f"bgp1.{created['registration_id']}.{created['pairing_secret']}"
    body = {
        "registration_id": created["registration_id"],
        "state": "pending",
        "expires_at": created["expires_at"],
        # Адрес ingress и код привязки отдаются один раз: сервер хранит только их digest.
        "ingress_url": runtime.ingress_url(created["capability"]),
        "pairing_code": code,
        "setup_url": f"{runtime.public_base_url}/push/setup#{code}",
    }
    return JSONResponse(body, status_code=201, headers=_NO_STORE)


@router.get("/registrations/{registration_id}")
async def get_registration(request: Request, registration_id: str) -> JSONResponse:
    ctx, runtime = _runtime(request)
    bearer = _bearer(request)
    _check_id(registration_id)
    at = now()

    def _work() -> dict[str, Any]:
        row = service.get_row(ctx.push_db.connection, registration_id)  # type: ignore[union-attr]
        role = service.role_for(row, runtime.vault, bearer)
        if row is None or role is None:
            raise unauthorized()
        return service.view(row, runtime.vault, at=at, owner=role == "owner")

    return JSONResponse(await ctx.push_db.run(_work), headers=_NO_STORE)  # type: ignore[union-attr]


@router.post("/registrations/{registration_id}/complete")
async def complete_registration(request: Request, registration_id: str, payload: CompleteIn) -> JSONResponse:
    """PWA завершает привязку. Секрет из кода одноразовый; повторно использовать его нельзя."""
    ctx, runtime = _runtime(request)
    secret = _bearer(request)
    _check_id(registration_id)
    ip = client_ip(request, ctx.settings) or "unknown"
    # Лимит по IP не даёт заполнять rate_events случайными id. Лимит по паре (id, IP) не позволяет
    # чужому адресу исчерпать попытки легитимного устройства.
    await _limit(
        ctx,
        scope="push_complete_ip",
        key=runtime.vault.digest("rate-complete-ip", ip),
        limit=ctx.settings.rl_push_complete_ip_per_15m,
        window_seconds=900,
        message="Слишком много попыток. Подождите и повторите.",
    )
    await _limit(
        ctx,
        scope="push_complete",
        key=runtime.vault.digest("rate-complete", f"{registration_id}|{ip}"),
        limit=ctx.settings.rl_push_complete_per_15m,
        window_seconds=900,
        message="Слишком много попыток. Подождите и повторите.",
    )
    at = now()
    data = payload.model_dump()

    def _work() -> str:
        with ctx.push_db.transaction() as conn:  # type: ignore[union-attr]
            return service.complete(
                conn,
                vault=runtime.vault,
                allowed_hosts=runtime.allowed_hosts,
                registration_id=registration_id,
                pairing_secret=secret,
                payload=data,
                at=at,
            )

    token = await ctx.push_db.run(_work)  # type: ignore[union-attr]
    return JSONResponse(
        {"registration_id": registration_id, "state": "active", "token": token},
        headers=_NO_STORE,
    )


@router.post("/registrations/{registration_id}/telegram-confirm")
async def confirm_telegram(request: Request, registration_id: str) -> dict[str, Any]:
    """Нативный клиент сообщает, что зарегистрировал ingress в Telegram (только владелец)."""
    ctx, runtime = _runtime(request)
    bearer = _bearer(request)
    _check_id(registration_id)
    at = now()

    def _work() -> Any:
        with ctx.push_db.transaction() as conn:  # type: ignore[union-attr]
            row = service.get_row(conn, registration_id)
            if service.role_for(row, runtime.vault, bearer) != "owner":
                raise unauthorized()
            return service.confirm_telegram(conn, registration_id=registration_id, at=at)

    confirmed_at = await ctx.push_db.run(_work)  # type: ignore[union-attr]
    return {"ok": True, "telegram_confirmed_at": confirmed_at}


@router.post("/registrations/{registration_id}/test", status_code=202)
async def send_test(request: Request, registration_id: str) -> dict[str, Any]:
    ctx, runtime = _runtime(request)
    bearer = _bearer(request)
    _check_id(registration_id)
    at = now()

    def _work() -> str:
        with ctx.push_db.transaction() as conn:  # type: ignore[union-attr]
            row = service.get_row(conn, registration_id)
            if service.role_for(row, runtime.vault, bearer) is None:
                raise unauthorized()
            return service.enqueue_test(
                conn, settings=ctx.settings, vault=runtime.vault, registration_id=registration_id, at=at
            )

    return {"test_id": await ctx.push_db.run(_work)}  # type: ignore[union-attr]


@router.post("/registrations/{registration_id}/ack")
async def ack_test(request: Request, registration_id: str, payload: AckIn) -> dict[str, Any]:
    ctx, runtime = _runtime(request)
    bearer = _bearer(request)
    _check_id(registration_id)
    at = now()

    def _work() -> bool:
        with ctx.push_db.transaction() as conn:  # type: ignore[union-attr]
            row = service.get_row(conn, registration_id)
            if service.role_for(row, runtime.vault, bearer) is None:
                raise unauthorized()
            return service.acknowledge(conn, registration_id=registration_id, test_id=payload.test_id, at=at)

    return {"acknowledged": await ctx.push_db.run(_work)}  # type: ignore[union-attr]


@router.delete("/registrations/{registration_id}")
async def delete_registration(request: Request, registration_id: str) -> dict[str, Any]:
    """Отзыв регистрации владельцем или самим устройством. Повторный вызов безопасен."""
    ctx, runtime = _runtime(request)
    bearer = _bearer(request)
    _check_id(registration_id)
    at = now()

    def _work() -> None:
        with ctx.push_db.transaction() as conn:  # type: ignore[union-attr]
            row = service.get_row(conn, registration_id)
            if service.role_for(row, runtime.vault, bearer) is None:
                raise unauthorized()
            service.revoke(conn, registration_id=registration_id, reason="client_deleted", at=at)

    await ctx.push_db.run(_work)  # type: ignore[union-attr]
    return {"deleted": True}


_LOG_TOKEN_RE = re.compile(r"^[a-z0-9.+/_-]{1,32}$")


def _log_token(value: str) -> str:
    """Значение заголовка для лога: короткий безопасный алфавит. Иное заменяется маркером."""
    if not value:
        return "absent"
    return value if _LOG_TOKEN_RE.match(value) else "invalid"


def _param_names(value: str) -> str:
    """Только имена параметров заголовка (salt, rs, dh и т. п.): значения соли и ключа в лог не попадают."""
    if not value:
        return "absent"
    names = [part.partition("=")[0].strip().lower() for part in re.split(r"[;,]", value) if "=" in part]
    return ",".join(_log_token(name) for name in names[:4]) or "invalid"


def _log_ingress(request: Request) -> None:
    """Одна строка на каждый приём: в каком формате прислала запись сторона Telegram. Путь и значения не пишем."""
    encoding = request.headers.get("content-encoding", "").strip().lower()
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    log.info(
        "push ingress: encoding=%s content_type=%s encryption_params=%s crypto_key_params=%s",
        _log_token(encoding),
        _log_token(content_type),
        _param_names(request.headers.get("encryption", "")),
        _param_names(request.headers.get("crypto-key", "")),
    )


def _aesgcm_body(request: Request, body: bytes) -> bytes:
    """Тело aesgcm переносится в конверт вместе с salt и dh из заголовков: PWA расшифрует его на устройстве."""
    try:
        return aesgcm_envelope(
            body,
            encryption=request.headers.get("encryption", ""),
            crypto_key=request.headers.get("crypto-key", ""),
        )
    except PushCryptoError:
        raise payload_invalid(message="Некорректные заголовки aesgcm или тело длиннее одной записи.") from None


async def _count_ingress_rejection(ctx: AppContext, code: str) -> None:
    """Попытка и причина отказа: суточные счётчики без идентификаторов.

    Отдельная транзакция: откат основной операции счётчик не затрагивает. Сбой учёта не должен менять
    ответ Telegram, поэтому ошибка здесь только логируется.
    """
    at = now()

    def _work() -> None:
        with ctx.push_db.transaction() as conn:  # type: ignore[union-attr]
            service.bump(conn, "ingress_attempt", at=at)
            service.bump(conn, f"ingress_rejected_{code}", at=at)

    try:
        await ctx.push_db.run(_work)  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001 - учёт не должен менять ответ
        log.warning("push ingress: counter update failed")


@router.post("/ingress/{capability}", status_code=201)
async def ingress(request: Request, capability: str) -> JSONResponse:
    """Приём Telegram Web Push. Capability в пути — секрет: в логах путь скрывается (middleware)."""
    ctx, runtime = _runtime(request)
    _log_ingress(request)
    try:
        await _store_ingress(request, ctx, runtime, capability)
    except ApiError as exc:
        await _count_ingress_rejection(ctx, exc.code)
        raise
    return JSONResponse({}, status_code=201, headers=_NO_STORE)


async def _store_ingress(request: Request, ctx: AppContext, runtime: PushRuntime, capability: str) -> None:
    """Проверки и постановка в очередь. Любой отказ — ApiError: обработчик его считает и отдаёт ответ."""
    settings = ctx.settings
    if not _CAPABILITY_RE.match(capability):
        raise ApiError(ERR_NOT_FOUND, "Ресурс не найден.", 404)
    encoding = request.headers.get("content-encoding", "").strip().lower()
    if encoding not in _SUPPORTED_ENCODINGS:
        raise ApiError("unsupported_encoding", "Поддерживаются aes128gcm и aesgcm.", 415)
    # Размер проверяем до чтения тела: сначала заявленная длина, затем поток с обрывом на лимите.
    limit = settings.push_max_ingress_bytes
    declared = (request.headers.get("content-length") or "").strip()
    if declared and (not declared.isascii() or not declared.isdigit() or len(declared) > 12 or int(declared) > limit):
        raise body_too_large(limit)
    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            raise body_too_large(limit)
        chunks.append(chunk)
    body = b"".join(chunks)
    if not body:
        raise payload_invalid(message="Пустое тело уведомления.")
    if encoding == _ENC_AESGCM:
        body = _aesgcm_body(request, body)
    ttl_raw = request.headers.get("ttl", "").strip()
    ttl = int(ttl_raw) if ttl_raw.isascii() and ttl_raw.isdigit() and len(ttl_raw) <= 9 else None
    await _limit(
        ctx,
        scope="push_ingress_global_ip",
        key=runtime.vault.digest("rate-ingress-ip", client_ip(request, settings) or "unknown"),
        limit=settings.rl_push_ingress_global_per_hour,
        window_seconds=3600,
        message="Превышен лимит входящих уведомлений.",
    )
    at = now()

    def _work() -> None:
        with ctx.push_db.transaction() as conn:  # type: ignore[union-attr]
            service.accept_ingress(
                conn,
                settings=settings,
                vault=runtime.vault,
                capability=capability,
                body=body,
                ttl=ttl,
                at=at,
            )

    await ctx.push_db.run(_work)  # type: ignore[union-attr]
