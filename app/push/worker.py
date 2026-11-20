"""Фоновый воркер BG Push: шифрование внешнего слоя, отправка провайдеру, учёт результата.

Цикл: maintenance -> claim (атомарная аренда задачи) -> отправка с параллелизмом
-> фиксация результата. Аренда (lease) не даёт двум итерациям взять одну задачу,
а зависшая задача возвращается в очередь по истечении срока аренды.

Результат записывается только для той попытки, которая держит аренду (номер попытки
совпадает с claim). Поздний ответ после перевыдачи задачи не перезаписывает состояние.

Журналы не содержат endpoint-ов, ключей и содержимого: только id задачи и код ответа.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx

from ..util import now
from . import service
from .crypto import PushCryptoError, encrypt_aes128gcm, vapid_authorization

if TYPE_CHECKING:
    from ..context import AppContext

log = logging.getLogger(__name__)

WORKER_NAME = "push-worker"
BATCH_SIZE = 25
_HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_MAX_RETRY_AFTER = 3600.0


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        return None
    return max(1.0, min(seconds, _MAX_RETRY_AFTER))


def _origin(endpoint: str) -> str:
    parts = urlsplit(endpoint)
    return f"{parts.scheme}://{parts.hostname}"


async def _tx(ctx: AppContext, fn: Any, **kwargs: Any) -> Any:
    """Выполняет запись в собственной транзакции под общим локом push-базы."""

    def _run() -> Any:
        with ctx.push_db.transaction() as conn:  # type: ignore[union-attr]
            return fn(conn, **kwargs)

    return await ctx.push_db.run(_run)  # type: ignore[union-attr]


async def process_once(ctx: AppContext, client: httpx.AsyncClient, *, at: float | None = None) -> int:
    """Одна итерация. Возвращает число задач, взятых в работу."""
    ts = at if at is not None else now()
    runtime = ctx.push
    settings = ctx.settings
    if runtime is None or ctx.push_db is None:
        return 0

    def _prepare() -> list[dict[str, Any]]:
        with ctx.push_db.transaction() as conn:  # type: ignore[union-attr]
            service.maintain(conn, at=ts, max_attempts=settings.push_worker_max_attempts)
            if not service.switch_enabled(conn, service.SWITCH_OUTBOUND):
                return []
            return service.claim_due(conn, at=ts, limit=BATCH_SIZE)

    claimed = await ctx.push_db.run(_prepare)  # type: ignore[union-attr]
    if not claimed:
        return 0
    semaphore = asyncio.Semaphore(max(1, settings.push_worker_concurrency))

    async def _one(item: dict[str, Any]) -> None:
        async with semaphore:
            await _deliver(ctx, client, item)

    await asyncio.gather(*(_one(item) for item in claimed))
    return len(claimed)


async def _deliver(ctx: AppContext, client: httpx.AsyncClient, item: dict[str, Any]) -> None:
    runtime = ctx.push
    assert runtime is not None and ctx.push_db is not None
    delivery_id = int(item["id"])
    rid = str(item["registration_id"])
    attempts = int(item["attempts"])
    try:
        if float(item["expires_at"]) <= now():
            await _tx(ctx, service.settle_expired, delivery_id=delivery_id, attempts=attempts)
            return

        def _target() -> service.PushTarget | None:
            return service.load_target(ctx.push_db.connection, runtime.vault, rid)  # type: ignore[union-attr]

        target = await ctx.push_db.run(_target)  # type: ignore[union-attr]
        if target is None:
            await _tx(
                ctx,
                service.settle_failure,
                delivery_id=delivery_id,
                registration_id=rid,
                attempts=attempts,
                status=None,
                error="registration_inactive",
                at=now(),
            )
            return

        body = encrypt_aes128gcm(bytes(item["body"]), ua_public=target.p256dh, auth_secret=target.auth)
        ts = now()
        headers = {
            "Content-Encoding": "aes128gcm",
            "Content-Type": "application/octet-stream",
            "TTL": str(max(0, int(float(item["expires_at"]) - ts))),
            "Urgency": "high",
            "Authorization": vapid_authorization(
                runtime.vapid,
                audience=_origin(target.endpoint),
                subject=runtime.subject,
                now=ts,
            ),
        }
        try:
            response = await client.post(target.endpoint, content=body, headers=headers)
        except httpx.InvalidURL:
            # Адрес, который httpx не разобрал, повторять бессмысленно. Текст исключения не логируем: он может содержать URL.
            await _tx(
                ctx,
                service.settle_failure,
                delivery_id=delivery_id,
                registration_id=rid,
                attempts=attempts,
                status=None,
                error="invalid_endpoint",
                at=now(),
            )
            return
        except httpx.HTTPError:
            await _retry_or_fail(ctx, item, status=None, error="transport", retry_after=None)
            return
        await _classify(ctx, item, response)
    except PushCryptoError:
        await _tx(
            ctx,
            service.settle_failure,
            delivery_id=delivery_id,
            registration_id=rid,
            attempts=attempts,
            status=None,
            error="crypto_error",
            at=now(),
        )
    except Exception as exc:  # noqa: BLE001 - задача не должна зависнуть в inflight
        # В журнал попадает только класс исключения: текст может содержать адрес или фрагменты данных.
        log.error(
            "push delivery failed unexpectedly",
            extra={"delivery_id": delivery_id, "attempts": attempts, "error_class": exc.__class__.__name__},
        )
        await _retry_or_fail(ctx, item, status=None, error="internal", retry_after=None)


async def _classify(ctx: AppContext, item: dict[str, Any], response: httpx.Response) -> None:
    delivery_id = int(item["id"])
    rid = str(item["registration_id"])
    attempts = int(item["attempts"])
    status = response.status_code
    if status in (201, 202):
        await _tx(
            ctx,
            service.settle_success,
            delivery_id=delivery_id,
            registration_id=rid,
            attempts=attempts,
            status=status,
            at=now(),
        )
        return
    if status in (404, 410):
        # Провайдер больше не знает подписку: регистрация отзывается, PWA нужна новая привязка.
        def _gone() -> None:
            with ctx.push_db.transaction() as conn:  # type: ignore[union-attr]
                # Сначала фиксируем результат, пока аренда задачи действительна. Затем revoke снимает очередь,
                # в том числе уже закрытую задачу не трогает: она уже не inflight.
                service.settle_failure(
                    conn,
                    delivery_id=delivery_id,
                    registration_id=rid,
                    attempts=attempts,
                    status=status,
                    error="provider_gone",
                    at=now(),
                )
                service.revoke(conn, registration_id=rid, reason="provider_gone", at=now())

        await ctx.push_db.run(_gone)  # type: ignore[union-attr]
        log.info("push subscription gone; registration revoked", extra={"status": status})
        return
    if status == 429 or status >= 500:
        await _retry_or_fail(
            ctx,
            item,
            status=status,
            error=f"provider_{status}",
            retry_after=_retry_after(response.headers.get("Retry-After")),
        )
        return
    # 400/401/403 (например, рассогласование VAPID), 413 и прочие: без повторов, видно в админке.
    await _tx(
        ctx,
        service.settle_failure,
        delivery_id=delivery_id,
        registration_id=rid,
        attempts=attempts,
        status=status,
        error=f"provider_{status}",
        at=now(),
    )


async def _retry_or_fail(
    ctx: AppContext,
    item: dict[str, Any],
    *,
    status: int | None,
    error: str,
    retry_after: float | None,
) -> None:
    delivery_id = int(item["id"])
    rid = str(item["registration_id"])
    attempts = int(item["attempts"])
    if attempts >= ctx.settings.push_worker_max_attempts:
        await _tx(
            ctx,
            service.settle_failure,
            delivery_id=delivery_id,
            registration_id=rid,
            attempts=attempts,
            status=status,
            error=f"{error}_exhausted",
            at=now(),
        )
        return
    await _tx(
        ctx,
        service.settle_retry,
        delivery_id=delivery_id,
        attempts=attempts,
        status=status,
        error=error,
        at=now(),
        retry_after=retry_after,
    )


async def run(ctx: AppContext) -> None:
    """Точка входа для supervisor-а AppContext."""
    limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, limits=limits, follow_redirects=False) as client:
        while not ctx.stopping.is_set():
            processed = 0
            try:
                processed = await process_once(ctx, client)
                ctx.worker_success(WORKER_NAME)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                ctx.worker_failure(WORKER_NAME, exc.__class__.__name__)
                log.exception("push worker iteration failed", extra={"worker": WORKER_NAME})
            delay = 0.05 if processed else ctx.settings.push_worker_poll_interval_seconds
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(ctx.stopping.wait(), timeout=delay)
