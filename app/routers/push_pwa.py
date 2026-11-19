"""Веб-компаньон BG Push: страницы установки PWA, привязки и перехода в BeyGram.

Отдаются только файлы из фиксированного каталога app/static/push. Код привязки
передаётся во фрагменте URL (#...). Фрагмент не уходит на сервер и не попадает в логи.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response

router = APIRouter(include_in_schema=False)

_ROOT = Path(__file__).resolve().parent.parent / "static" / "push"
_ASSETS = _ROOT / "assets"
_PAGE_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; manifest-src 'self'; worker-src 'self'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    ),
}
_ASSET_TYPES = {
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".png": "image/png",
}


def _enabled(request: Request) -> bool:
    return bool(request.app.state.context.settings.enable_push)


def _not_found() -> JSONResponse:
    return JSONResponse(
        {"error": {"code": "not_found", "message": "Ресурс не найден."}},
        status_code=404,
        headers={"Cache-Control": "no-store"},
    )


def _page(request: Request, name: str, media_type: str, extra: dict[str, str] | None = None) -> Response:
    if not _enabled(request):
        return _not_found()
    return FileResponse(_ROOT / name, media_type=media_type, headers={**_PAGE_HEADERS, **(extra or {})})


@router.get("/push")
async def push_root(request: Request) -> Response:
    if not _enabled(request):
        return _not_found()
    return RedirectResponse("/push/", status_code=308)


@router.get("/push/")
async def push_index(request: Request) -> Response:
    return _page(request, "index.html", "text/html; charset=utf-8")


@router.get("/push/setup")
async def push_setup(request: Request) -> Response:
    return _page(request, "setup.html", "text/html; charset=utf-8")


@router.get("/push/open")
async def push_open(request: Request) -> Response:
    return _page(request, "open.html", "text/html; charset=utf-8")


@router.get("/push/sw.js")
async def push_service_worker(request: Request) -> Response:
    return _page(
        request,
        "sw.js",
        "text/javascript; charset=utf-8",
        {"Service-Worker-Allowed": "/push/", "Cache-Control": "no-cache"},
    )


@router.get("/push/manifest.webmanifest")
async def push_manifest(request: Request) -> Response:
    return _page(
        request,
        "manifest.webmanifest",
        "application/manifest+json; charset=utf-8",
        {"Cache-Control": "public, max-age=3600"},
    )


@router.get("/push/assets/{asset_path:path}")
async def push_asset(request: Request, asset_path: str) -> Response:
    if not _enabled(request):
        return _not_found()
    base = _ASSETS.resolve()
    target = (base / asset_path).resolve()
    if base not in target.parents or not target.is_file():
        return _not_found()
    media_type = _ASSET_TYPES.get(target.suffix.lower())
    if media_type is None:
        return _not_found()
    return FileResponse(
        target,
        media_type=media_type,
        headers={"Cache-Control": "public, max-age=3600", "X-Content-Type-Options": "nosniff"},
    )
