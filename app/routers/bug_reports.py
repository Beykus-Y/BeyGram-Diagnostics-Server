"""Роутер приёма отчётов: POST /api/v1/bug-reports и GET статуса."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import ValidationError

from ..config import Settings
from ..context import AppContext
from ..dependencies import bearer_nonce, client_ip, get_context, get_settings_dep, status_token_from_request
from ..errors import payload_invalid, unauthorized
from ..schemas import AcceptedBugReport, BugReportIn, BugReportStatus
from ..services import intake
from ..util import now

log = logging.getLogger(__name__)

router = APIRouter(prefix="/bug-reports", tags=["bug-reports"])

ContextDep = Annotated[AppContext, Depends(get_context)]
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


@router.post("", response_model=AcceptedBugReport, status_code=202)
async def create_bug_report(
    request: Request,
    ctx: ContextDep,
    settings: SettingsDep,
) -> AcceptedBugReport:
    """Принимает диагностический отчёт, подтверждённый через Telegram-бота.

    Токен доступа — заголовок Authorization: Bearer <nonce>.
    Поля telegram_user_id в теле нет: сервер доверяет только from.id, который
    бот получил от Bot API при подтверждении nonce.
    """
    nonce = bearer_nonce(request)
    body = await request.body()
    body_bytes = len(body)

    if body_bytes == 0:
        raise payload_invalid(message="Тело запроса пустое.")

    try:
        payload = BugReportIn.model_validate_json(body)
    except ValidationError as exc:
        # Отдаём только пути и типы ошибок, без значений — они могут содержать
        # то, что клиент не должен показывать в логах.
        details = [
            {"loc": list(err.get("loc", ())), "type": err.get("type", "invalid")}
            for err in exc.errors()[:20]
        ]
        raise payload_invalid(details) from None

    ip = client_ip(request, settings)

    result = await intake.submit_report(
        ctx.db,
        settings,
        payload=payload,
        nonce=nonce,
        client_ip=ip,
        body_bytes=body_bytes,
    )

    return AcceptedBugReport(
        report_id=result.report_id,
        status=result.status,
        accepted_at=result.accepted_at,
        status_token=result.status_token,
        idempotent_replay=result.idempotent_replay,
        redactions=result.redactions,
        detail=result.detail,
    )


@router.get("/{report_id}", response_model=BugReportStatus)
async def get_bug_report_status(
    report_id: str,
    request: Request,
    ctx: ContextDep,
    settings: SettingsDep,
) -> BugReportStatus:
    """Возвращает состояние отчёта по подписанному status-токену."""
    from ..util import is_uuid4

    if not is_uuid4(report_id):
        raise unauthorized()

    token = status_token_from_request(request)
    if not token:
        raise unauthorized()

    result = await intake.get_status(
        ctx.db, settings, report_id=report_id, status_token=token
    )
    return BugReportStatus(
        report_id=result.report_id,
        status=result.status,
        accepted_at=result.accepted_at,
        updated_at=result.updated_at,
        delivered_at=result.delivered_at,
        attempts=result.attempts,
        detail=result.detail,
    )


__all__ = ["router", "now"]
