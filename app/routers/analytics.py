"""Automatic telemetry endpoint; independent of manual /report confirmation."""

from __future__ import annotations

import re
from typing import Annotated, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..dependencies import client_ip
from ..errors import ApiError, rate_limited, unauthorized
from ..repository import analytics, rate_limit
from ..security import hash_ip, validate_nonce
from ..util import is_uuid4, now

router = APIRouter(prefix="/analytics", tags=["analytics"])
_VERSION = Annotated[str, Field(min_length=1, max_length=40, pattern=r"^[A-Za-z0-9._+\-]+$")]
_OS = Annotated[str, Field(min_length=1, max_length=40, pattern=r"^[A-Za-z0-9 ._\-]+$")]
_DEVICE = Annotated[str, Field(min_length=1, max_length=80)]
_USER_ID = Annotated[int, Field(strict=True, ge=1, le=9223372036854775807)]


class SyncIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    installation_id: str
    revision: int = Field(strict=True, ge=0, le=9223372036854775807)
    app_version: _VERSION
    app_version_code: int = Field(strict=True, ge=0, le=2147483647)
    release_channel: Literal["stable", "dev"]
    android_version: _OS
    device_model: _DEVICE | None = None
    account_count: int = Field(strict=True, ge=0, le=20)
    telegram_user_ids: list[_USER_ID] | None = Field(default=None, max_length=20)

    @field_validator("device_model")
    @classmethod
    def check_device_model(cls, value: str | None) -> str | None:
        if value is not None and not value.isprintable():
            raise ValueError("device_model must be printable")
        return value

    @field_validator("installation_id")
    @classmethod
    def check_uuid(cls, value: str) -> str:
        if not is_uuid4(value):
            raise ValueError("installation_id must be canonical UUIDv4")
        return value.lower()


def _credential(request: Request) -> str:
    header = request.headers.get("authorization", "")
    match = re.fullmatch(r"Bearer\s+([A-Za-z0-9_-]{43})", header.strip(), flags=re.IGNORECASE)
    if not match:
        raise unauthorized()
    token = match.group(1)
    try:
        validate_nonce(token)  # 256-bit random secret, same secure shape; NOT report flow.
    except ValueError:
        raise unauthorized() from None
    return token


@router.post("/sync")
async def sync_installation(request: Request, payload: SyncIn) -> dict:
    """Register immediately on first launch; never require Telegram login/bot."""
    ctx = request.app.state.context
    settings = ctx.settings
    if not settings.accept_analytics:
        raise ApiError("analytics_disabled", "Analytics ingestion is disabled.", 503)
    digest = analytics.token_digest(_credential(request))
    ip_digest = hash_ip(settings.nonce_pepper, client_ip(request, settings))
    timestamp = now()

    def work() -> dict:
        with ctx.db.transaction() as conn:
            for scope, key, limit, window in (
                ("analytics_ip", ip_digest, settings.rl_analytics_ip_per_hour, 3600),
                ("analytics_global", None, settings.rl_analytics_global_per_day, 86400),
            ):
                ok, delay = rate_limit.check_and_record(
                    conn, scope=scope, key=key, limit=limit, window_seconds=window, at=timestamp
                )
                if not ok:
                    raise rate_limited(max(1, int(delay)), "Analytics rate limit reached.")
            existing = conn.execute(
                "SELECT 1 FROM analytics_installations WHERE installation_id=?",
                (payload.installation_id,),
            ).fetchone()
            if existing is None:
                ok, delay = rate_limit.check_and_record(
                    conn, scope="analytics_registration_ip", key=ip_digest,
                    limit=settings.rl_analytics_registrations_per_day, window_seconds=86400,
                    at=timestamp,
                )
                if not ok:
                    raise rate_limited(max(1, int(delay)), "Registration rate limit reached.")
            try:
                created, accepted, _beta = analytics.upsert(
                    conn, installation_id=payload.installation_id, digest=digest,
                    revision=payload.revision, version=payload.app_version,
                    version_code=payload.app_version_code, channel=payload.release_channel,
                    android_version=payload.android_version, device_model=payload.device_model,
                    account_count=payload.account_count, user_ids=payload.telegram_user_ids,
                    at=timestamp,
                )
            except PermissionError:
                raise unauthorized() from None
            return {"registered": created, "updated": accepted}

    return await ctx.db.run(work)


@router.delete("/installations/{installation_id}")
async def delete_installation(request: Request, installation_id: str) -> dict:
    """Delete own installation with its secret, also when intake is disabled."""
    if not is_uuid4(installation_id):
        raise unauthorized()
    installation_id = installation_id.lower()
    ctx = request.app.state.context
    digest = analytics.token_digest(_credential(request))

    def work() -> None:
        with ctx.db.transaction() as conn:
            if not analytics.erase(conn, installation_id, digest):
                raise unauthorized()

    await ctx.db.run(work)
    return {"deleted": True}
