"""Административная веб-панель (включается ADMIN_TOKEN'ом).

Безопасность:
* панель полностью выключена (404), пока ADMIN_TOKEN пуст — по умолчанию;
* вход по единому админ-токену (constant-time сравнение), сессия — подписанная
  HMAC(pepper) cookie: HttpOnly, SameSite=Strict, Secure при require_https;
* CSRF-токен привязан к сессии и обязателен для всех write-действий;
* попытки входа ограничены rate limit'ом по IP (псевдонимизированному);
* ответы без кеширования, с анти-clickjacking и CSP-заголовками;
* весь вывод экранируется (html.escape) — диагностические строки недоверенные;
* сырые nonce, бот-токены и pepper никогда не отображаются; содержимое отчётов
  уже отредактировано при приёме;
* каждое write-действие попадает в audit_log с actor="admin".

Панель не запускает собственных воркеров и работает с той же БД в коротких
транзакциях (SQLite single-writer соблюдается).

Развертывание: НЕ открывать панель в публичный интернет напрямую. Использовать
приватную сеть или identity-aware reverse proxy перед приложением.
"""

from __future__ import annotations

import html
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response

from .. import admin_sessions
from ..config import Settings
from ..db import Database
from ..repository import allowlist, audit, nonces, rate_limit, reports
from ..security import constant_time_equals, hash_ip
from ..services.settings_service import intake_enabled, set_intake_enabled

log = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])

_SCOPE_ADMIN_LOGIN = "admin_login"
_PAGE_SIZE = 25
_STYLESHEET = Path(__file__).resolve().parent.parent / "static" / "admin.css"


# --- Подписи и сессии -------------------------------------------------------


# --- Сессии (см. app/admin_sessions.py) -------------------------------------


def _guard(request: Request, settings: Settings, session) -> tuple[float, str] | Response:
    """Проверяет доступ: панель включена и сессия действительна.

    `session` — результат read_session (считается обработчиком через db.run,
    поскольку реестр сессий живёт в БД). Возвращает сессию либо готовый
    Response (404 при выключенной панели, редирект на логин).
    """
    if not settings.admin_token:
        return _not_found()
    if session is None:
        return RedirectResponse("/admin/login", status_code=303)
    return session


def _telegram_user_id(raw: object) -> int | None:
    """Строго положительный SQLite INTEGER/TG user_id из HTML формы."""
    if not isinstance(raw, str) or not raw.isascii() or not raw.isdigit():
        return None
    if not (1 <= len(raw) <= 19):
        return None
    value = int(raw)
    return value if 0 < value <= 2**63 - 1 else None


def _check_csrf(session: tuple[float, str], form: dict[str, Any]) -> bool:
    token = form.get("csrf")
    return isinstance(token, str) and constant_time_equals(token, session[1])


# --- Ответы -----------------------------------------------------------------


def _secure_headers() -> dict[str, str]:
    return {
        "Cache-Control": "no-store",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    }


@router.get("/assets/admin.css", include_in_schema=False)
async def admin_stylesheet(request: Request) -> Response:
    """Только локальный CSS админки; при выключенной панели отдаём 404."""
    if not request.app.state.context.settings.admin_token:
        return _not_found()
    return FileResponse(
        _STYLESHEET,
        media_type="text/css; charset=utf-8",
        headers={"Cache-Control": "private, max-age=3600", "X-Content-Type-Options": "nosniff"},
    )


def _page(title: str, body: str) -> HTMLResponse:
    safe_title = html.escape(title)
    return HTMLResponse(
        content=(
            "<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<meta name='theme-color' content='#6357d9'>"
            f"<title>{safe_title} — BeyGram Diagnostics</title>"
            "<link rel='stylesheet' href='/admin/assets/admin.css'>"
            "</head><body><div class='shell'>"
            "<header class='topbar'>"
            "<a class='brand' href='/admin'><span class='brand-mark' aria-hidden='true'>B</span>"
            "<span class='brand-copy'>BeyGram<small>Diagnostics console</small></span></a>"
            "<nav class='nav-links' aria-label='Управление'>"
            "<a href='/admin'>Обзор</a><a href='/admin/reports'>Отчёты</a>"
            "<a href='/admin/testers'>Доступ</a><a href='/admin/analytics'>Аналитика</a><a href='/admin/audit'>Аудит</a></nav>"
            "<form method='post' action='/admin/logout'>"
            "<button class='btn secondary' type='submit'>Выйти</button></form>"
            "</header><header class='page-header'>"
            "<div class='eyebrow'>BeyGram / Administration</div>"
            f"<h1>{safe_title}</h1></header>"
            f"<main class='main-panel'>{body}</main>"
            "<footer class='footer'>BeyGram Diagnostics · доступ только для администратора</footer>"
            "</div></body></html>"
        ),
        headers=_secure_headers(),
    )


def _not_found() -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={"error": {"code": "not_found", "message": "Ресурс не найден."}},
        headers=_secure_headers(),
    )


# --- Хелперы данных ---------------------------------------------------------


def _fmt_ts(ts: float | None) -> str:
    if not ts:
        return "—"
    from datetime import UTC, datetime

    try:
        return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "?"


def _status_badge(status: str) -> str:
    classes = {
        "DELIVERED": "ok",
        "FAILED": "bad",
        "DROPPED": "bad",
        "QUEUED": "",
        "PROCESSING": "",
    }
    css = classes.get(status, "")
    return f"<span class='{css}'>{html.escape(status)}</span>"


# --- Логин/выход ------------------------------------------------------------


@router.get("/login")
async def login_page(request: Request) -> Response:
    ctx = request.app.state.context
    settings: Settings = ctx.settings
    if not settings.admin_token:
        return _not_found()
    session = await ctx.db.run(
        lambda: admin_sessions.read_session(
            ctx.db.connection, settings, request.cookies.get(admin_sessions.COOKIE_NAME)
        )
    )
    if session is not None:
        return RedirectResponse("/admin", status_code=303)
    return _page(
        "Вход",
        "<form method='post' action='/admin/login'>"
        "<p><input type='password' name='token' placeholder='ADMIN_TOKEN' "
        "autocomplete='current-password' required></p>"
        "<button class='btn' type='submit'>Войти</button></form>",
    )


@router.post("/login")
async def login(request: Request) -> Response:
    ctx = request.app.state.context
    settings: Settings = ctx.settings
    db: Database = ctx.db
    if not settings.admin_token:
        return _not_found()

    form = dict(await request.form())
    submitted = form.get("token")
    submitted = submitted if isinstance(submitted, str) else ""

    from ..dependencies import client_ip  # noqa: PLC0415

    ip = client_ip(request, settings)

    def _limited() -> bool:
        ok, _ = rate_limit.check_and_record(
            db.connection,
            scope=_SCOPE_ADMIN_LOGIN,
            key=hash_ip(settings.nonce_pepper, ip),
            limit=settings.admin_login_attempts_per_hour,
            window_seconds=3600,
        )
        return not ok

    limited = await db.run(_limited)
    if limited:
        return _page("Вход", "<p class='bad'>Слишком много попыток входа. Попробуйте позже.</p>")

    if not constant_time_equals(submitted, settings.admin_token):
        await db.run(
            lambda: _audit(db, "admin_login_failed", {"ip_pseudonym": bool(ip)})
        )
        page = _page(
            "Ошибка входа",
            "<p class='bad'>Неверный токен.</p>"
            "<p><a href='/admin/login'>Попробовать снова</a></p>",
        )
        page.status_code = 401
        return page

    async def _create_session() -> str:
        # Замыкание: создаёт запись сессии в реестре в короткой транзакции.
        def _do() -> str:
            cookie, _ = admin_sessions.create_session(db.connection, settings)
            return cookie

        return await db.run(_do)

    cookie = await _create_session()
    await db.run(lambda: _audit(db, "admin_login", {}))
    response = RedirectResponse("/admin", status_code=303)
    response.set_cookie(
        admin_sessions.COOKIE_NAME,
        cookie,
        max_age=settings.admin_session_ttl_seconds,
        httponly=True,
        samesite="strict",
        secure=settings.require_https,
        path="/admin",
    )
    return response


@router.post("/logout")
async def logout(request: Request) -> Response:
    """Выход: сессия отзывается на сервере, а не только в браузере.

    Сохранённая копия cookie после logout становится недействительной:
    реестр сессий больше не содержит её id.
    """
    ctx = request.app.state.context
    cookie_value = request.cookies.get(admin_sessions.COOKIE_NAME)
    if cookie_value:
        await ctx.db.run(
            lambda: admin_sessions.revoke_session(ctx.db.connection, cookie_value)
        )
    response = RedirectResponse("/admin/login", status_code=303)
    response.delete_cookie(admin_sessions.COOKIE_NAME, path="/admin")
    return response


def _audit(db: Database, action: str, detail: dict[str, Any]) -> None:
    with db.transaction() as conn:
        audit.write(conn, actor="admin", action=action, detail=detail or None)


async def _session(ctx, request: Request) -> tuple[float, str] | None:
    """Читает сессию из серверного реестра (в БД)."""
    return await ctx.db.run(
        lambda: admin_sessions.read_session(
            ctx.db.connection,
            ctx.settings,
            request.cookies.get(admin_sessions.COOKIE_NAME),
        )
    )


# --- Обзор ------------------------------------------------------------------


@router.get("")
@router.get("/")
async def overview(request: Request) -> Response:
    ctx = request.app.state.context
    settings: Settings = ctx.settings
    guarded = _guard(request, settings, await _session(ctx, request))
    if isinstance(guarded, Response):
        return guarded
    db: Database = ctx.db

    def _stats() -> dict[str, Any]:
        with db.transaction() as conn:
            return {
                "queue": reports.queue_stats(conn),
                "queue_depth": reports.queue_depth(conn),
                "oldest": reports.oldest_queued_age(conn),
                "nonces": nonces.count_by_state(conn),
                "allowlist": allowlist.count_entries(conn),
                "intake": intake_enabled(conn, settings),
                "integrity": db.integrity_check(),
            }

    stats = await db.run(_stats)
    workers_html = "".join(
        f"<tr><td>{html.escape(name)}</td><td>{'да' if entry.running else '<b>нет</b>'}</td>"
        f"<td>{_fmt_ts(entry.last_success_at)}</td>"
        f"<td>{entry.consecutive_failures}</td><td>{entry.restarts}</td>"
        f"<td>{html.escape(entry.last_error or '—')}</td></tr>"
        for name, entry in sorted(ctx.health.items())
    ) or "<tr><td colspan='6' class='muted'>воркеры не запущены</td></tr>"

    queue = stats["queue"]
    rows = "".join(
        f"<tr><td>{html.escape(str(k))}</td><td>{v}</td></tr>" for k, v in sorted(queue.items())
    )
    intake_label = "включён" if stats["intake"] else "<b>выключен</b>"
    toggle_action = "off" if stats["intake"] else "on"

    body = (
        f"<p>Приём отчётов: {intake_label}.</p>"
        "<form class='inline' method='post' action='/admin/intake'>"
        f"<input type='hidden' name='csrf' value='{guarded[1]}'>"
        f"<input type='hidden' name='action' value='{toggle_action}'>"
        f"<button class='btn' type='submit'>{'Выключить приём' if stats['intake'] else 'Включить приём'}</button>"
        "</form>"
        "<h2>Очередь</h2>"
        f"<table><tr><th>состояние</th><th>кол-во</th></tr>{rows}"
        f"<tr><td>глубина</td><td>{stats['queue_depth']}</td></tr>"
        f"<tr><td>старейший в очереди</td><td>{stats['oldest'] and round(stats['oldest']) or 0} c</td></tr></table>"
        "<h2>Nonce</h2><table><tr><th>состояние</th><th>кол-во</th></tr>"
        + "".join(
            f"<tr><td>{html.escape(str(k))}</td><td>{v}</td></tr>"
            for k, v in sorted(stats["nonces"].items())
        )
        + f"</table><p>Тестировщиков: {stats['allowlist'].get('active', 0)} активных, "
        f"{stats['allowlist'].get('total', 0)} всего. Целостность БД: {html.escape(str(stats['integrity']))}.</p>"
        "<h2>Фоновые воркеры</h2>"
        "<table><tr><th>воркер</th><th>работает</th><th>последний успех</th>"
        "<th>сбоев подряд</th><th>рестартов</th><th>последняя ошибка</th></tr>"
        f"{workers_html}</table>"
    )
    return _page("Обзор", body)


# --- Analytics ---------------------------------------------------------------


@router.get("/analytics")
async def analytics_page(
    request: Request, status: str = "all", channel: str = "all",
    version: str = "", page: int = 1,
) -> Response:
    """Private installation dashboard; never show Telegram user IDs."""
    from urllib.parse import urlencode

    from ..repository import analytics as analytics_storage
    from ..util import now

    ctx = request.app.state.context
    guarded = _guard(request, ctx.settings, await _session(ctx, request))
    if isinstance(guarded, Response):
        return guarded
    timestamp = now()
    page = min(max(1, page), 100000)
    version = version.strip()[:40]
    db: Database = ctx.db

    def read():
        summary = analytics_storage.dashboard(db.connection, at=timestamp)
        records, total = analytics_storage.installations(
            db.connection, at=timestamp, status=status, channel=channel,
            version=version, page=page, page_size=25,
        )
        updates = analytics_storage.recent_updates(db.connection)
        return summary, records, total, updates

    summary, records, total, updates = await db.run(read)

    def value(number: int) -> str:
        return str(number)

    def small_table(heading: str, values: list[dict]) -> str:
        rows = "".join(
            f"<tr><td>{html.escape(str(row['name']))}</td><td>{row['count']}</td></tr>"
            for row in values
        ) or "<tr><td colspan='2' class='muted'>Пока нет данных</td></tr>"
        return f"<h2>{html.escape(heading)}</h2><table><tr><th>Значение</th><th>Установки</th></tr>{rows}</table>"

    select_status = status if status in {"all", "approved", "not_approved", "unknown"} else "all"
    select_channel = channel if channel in {"all", "stable", "dev"} else "all"
    filters = (
        ("all", "Все"),
        ("approved", "Да"),
        ("not_approved", "Нет"),
        ("unknown", "Не определён"),
    )
    options = "".join(
        f"<option value='{key}'{' selected' if select_status == key else ''}>{label}</option>"
        for key, label in filters
    )
    channel_options = "".join(
        f"<option value='{key}'{' selected' if select_channel == key else ''}>{label}</option>"
        for key, label in (("all", "Все"), ("stable", "Stable"), ("dev", "Dev"))
    )
    rows = "".join(
        "<tr>"
        f"<td><code>{html.escape(row['installation_id'][:8])}…</code></td>"
        f"<td>{html.escape(row['app_version'])}</td>"
        f"<td>{html.escape(row['release_channel'])}</td>"
        f"<td>{html.escape(row['android_version'])}</td>"
        f"<td>{html.escape(row['device_model'] or '—')}</td>"
        f"<td>{row['account_count']}</td>"
        f"<td>{html.escape(row['beta_status'])}</td>"
        f"<td>{_fmt_ts(row['first_seen_at'])}</td>"
        f"<td>{_fmt_ts(row['last_seen_at'])}</td>"
        "</tr>"
        for row in records
    ) or "<tr><td colspan='9' class='muted'>Установки не найдены</td></tr>"
    params = {"status": select_status, "channel": select_channel, "version": version}
    pager = ""
    if page > 1:
        pager += f"<a class='btn secondary' href='/admin/analytics?{html.escape(urlencode({**params, 'page': page - 1}), quote=True)}'>← Назад</a> "
    if page * 25 < total:
        pager += f"<a class='btn secondary' href='/admin/analytics?{html.escape(urlencode({**params, 'page': page + 1}), quote=True)}'>Далее →</a>"
    beta = summary["beta"]
    beta_rows = [
        {"name": name, "count": beta.get(name, 0)}
        for name in ("approved", "not_approved", "unknown")
    ]
    daily_rows = "".join(
        f"<tr><td>{html.escape(row['day'])}</td><td>{row['count']}</td></tr>"
        for row in summary["daily"]
    ) or "<tr><td colspan='2' class='muted'>Пока нет данных</td></tr>"
    update_rows = "".join(
        "<tr>"
        f"<td><code>{html.escape(row['installation_id'][:8])}…</code></td>"
        f"<td>{html.escape(row['previous_version'])}</td>"
        f"<td>{html.escape(row['current_version'])}</td>"
        f"<td>{_fmt_ts(row['recorded_at'])}</td>"
        "</tr>"
        for row in updates
    ) or "<tr><td colspan='4' class='muted'>Пока нет обновлений</td></tr>"
    body = (
        "<p class='muted'>Статистика по установкам, не по уникальным людям. "
        "Сырые Telegram ID не сохраняются в аналитике. "
        "Бета-статус старше 24 часов считается неизвестным.</p>"
        "<div class='kpi-strip'>"
        f"<div class='kpi'><b>{value(summary['total'])}</b><span>Всего установок</span></div>"
        f"<div class='kpi'><b>{value(summary['dau'])}</b><span>За 24 часа</span></div>"
        f"<div class='kpi'><b>{value(summary['wau'])}</b><span>За 7 дней</span></div>"
        f"<div class='kpi'><b>{value(summary['mau'])}</b><span>За 30 дней</span></div>"
        f"<div class='kpi'><b>{value(summary['new_30d'])}</b><span>Новых за 30 дней</span></div>"
        f"<div class='kpi'><b>{value(summary['account_slots'])}</b><span>Аккаунтов на установках</span></div>"
        "</div>"
        + small_table("Участие в бета-тесте", beta_rows)
        + small_table("Версии клиента", summary["versions"])
        + small_table("Каналы", summary["channels"])
        + small_table("Android", summary["android"])
        + f"<h2>Активность по дням</h2><table><tr><th>День (UTC)</th><th>Установки</th></tr>{daily_rows}</table>"
        + f"<h2>Последние обновления</h2><table><tr><th>Установка</th><th>Было</th><th>Стало</th><th>Когда</th></tr>{update_rows}</table>"
        "<h2>Установки</h2><form class='form-row' method='get' action='/admin/analytics'>"
        f"<div class='field'><label>Бета-тестер?</label><select name='status'>{options}</select></div>"
        f"<div class='field'><label>Канал</label><select name='channel'>{channel_options}</select></div>"
        f"<div class='field'><label>Версия</label><input name='version' maxlength='40' value='{html.escape(version, quote=True)}'></div>"
        "<button class='btn secondary' type='submit'>Фильтр</button></form>"
        f"<p class='muted'>Показано: {len(records)} из {total} · страница {page}</p>"
        "<div class='table-scroll'><table><thead><tr>"
        "<th>ID установки</th><th>Версия</th><th>Канал</th><th>Android</th>"
        "<th>Модель</th><th>Аккаунты</th><th>Бета-тестер?</th>"
        "<th>Первый запуск</th><th>Активность</th>"
        f"</tr></thead><tbody>{rows}</tbody></table></div><p>{pager}</p>"
    )
    return _page("Аналитика BeyGram", body)


# --- Отчёты -----------------------------------------------------------------


@router.get("/reports")
async def reports_page(request: Request, q: str = "", status: str = "", page: int = 1) -> Response:
    ctx = request.app.state.context
    settings: Settings = ctx.settings
    guarded = _guard(request, settings, await _session(ctx, request))
    if isinstance(guarded, Response):
        return guarded
    db: Database = ctx.db
    page = max(1, page)
    offset = (page - 1) * _PAGE_SIZE

    def _load() -> tuple[list, int]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status.upper())
        if q:
            qq = q.strip()
            if qq.isdigit():
                clauses.append("telegram_user_id = ?")
                params.append(int(qq))
            elif len(qq) >= 8:
                clauses.append("report_id LIKE ?")
                params.append(qq.lower() + "%")
            else:
                clauses.append("app_version LIKE ?")
                params.append(f"%{qq}%")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with db.transaction() as conn:
            rows = conn.execute(
                "SELECT report_id, telegram_user_id, status, attempts, app_version,"
                " created_at, last_error FROM reports "
                + where
                + " ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (*params, _PAGE_SIZE + 1, offset),
            ).fetchall()
            total = conn.execute(
                "SELECT COUNT(*) AS c FROM reports " + where, params
            ).fetchone()["c"]
        return rows, int(total)

    rows, total = await db.run(_load)
    has_more = len(rows) > _PAGE_SIZE
    rows = rows[:_PAGE_SIZE]

    items = "".join(
        "<tr>"
        f"<td><a href='/admin/reports/{row['report_id']}'>{row['report_id'][:8]}…</a></td>"
        f"<td>{row['telegram_user_id']}</td>"
        f"<td>{_status_badge(row['status'])}</td>"
        f"<td>{row['attempts']}</td>"
        f"<td>{html.escape(row['app_version'] or '—')}</td>"
        f"<td>{_fmt_ts(row['created_at'])}</td>"
        f"<td>{html.escape((row['last_error'] or '—')[:60])}</td>"
        "</tr>"
        for row in rows
    ) or "<tr><td colspan='7' class='muted'>ничего не найдено</td></tr>"

    nav_bits = []
    if page > 1:
        nav_bits.append(
            f"<a href='/admin/reports?page={page - 1}&q={html.escape(q)}&status={html.escape(status)}'>← назад</a>"
        )
    if has_more:
        nav_bits.append(
            f"<a href='/admin/reports?page={page + 1}&q={html.escape(q)}&status={html.escape(status)}'>вперёд →</a>"
        )

    body = (
        "<form method='get' action='/admin/reports'>"
        f"<input name='q' value='{html.escape(q)}' placeholder='report_id / user id / версия'>"
        f"<input name='status' value='{html.escape(status)}' placeholder='статус' size='10'>"
        "<button class='btn' type='submit'>Найти</button></form>"
        f"<p class='muted'>всего: {total}</p>"
        "<table><tr><th>report_id</th><th>user</th><th>статус</th><th>попытки</th>"
        "<th>версия</th><th>создан</th><th>ошибка</th></tr>"
        f"{items}</table><p>{' '.join(nav_bits)}</p>"
    )
    return _page("Отчёты", body)


@router.get("/reports/{report_id}")
async def report_detail(request: Request, report_id: str, severity: str = "", kind: str = "") -> Response:
    ctx = request.app.state.context
    settings: Settings = ctx.settings
    guarded = _guard(request, settings, await _session(ctx, request))
    if isinstance(guarded, Response):
        return guarded
    db: Database = ctx.db

    record = await db.run(lambda: reports.get(db.connection, report_id))
    if record is None:
        return _not_found()

    events = record.events()
    if severity:
        events = [e for e in events if (e.get("severity") or "") == severity.lower()]
    if kind:
        events = [e for e in events if (e.get("kind") or "") == kind.lower()]

    event_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(e.get('seq') or i))}</td>"
        f"<td>{html.escape(str(e.get('severity') or 'info'))}</td>"
        f"<td>{html.escape(str(e.get('kind') or 'other'))}</td>"
        f"<td>{html.escape(str(e.get('code') or '—'))}</td>"
        f"<td>{html.escape(str(e.get('message') or ''))}</td>"
        f"<td>{html.escape(json.dumps(e.get('attrs') or {}, ensure_ascii=False))}</td>"
        "</tr>"
        for i, e in enumerate(events[:500], start=1)
    ) or "<tr><td colspan='6' class='muted'>нет событий</td></tr>"

    retry_button = ""
    if record.status == "FAILED":
        retry_button = (
            "<form class='inline' method='post' action="
            f"'/admin/reports/{record.report_id}/retry'>"
            f"<input type='hidden' name='csrf' value='{guarded[1]}'>"
            "<button class='btn' type='submit'>Повторить доставку</button></form>"
        )

    meta = record.client_meta()
    meta_html = "".join(
        f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>"
        for k, v in sorted(meta.items())
    ) or "<tr><td colspan='2' class='muted'>—</td></tr>"

    body = (
        f"<p>{_status_badge(record.status)} · попыток: {record.attempts}/{record.max_attempts} · "
        f"частей доставлено: {record.delivered_parts} · user: {record.telegram_user_id}</p>"
        f"<p>Создан: {_fmt_ts(record.created_at)} · Доставлен: {_fmt_ts(record.delivered_at)}</p>"
        f"<p class='bad'>{html.escape(record.last_error or '')}</p>"
        f"{retry_button} <a class='btn' href='/admin/reports/{record.report_id}/export.json'>Экспорт JSON</a>"
        "<h2>Описание</h2><pre>" + html.escape(record.description or "") + "</pre>"
        "<h2>Сводка</h2><pre>" + html.escape(record.summary or "—") + "</pre>"
        "<h2>Метаданные клиента</h2><table><tr><th>поле</th><th>значение</th></tr>"
        f"{meta_html}</table>"
        "<h2>События</h2>"
        "<form method='get' action="
        f"'/admin/reports/{record.report_id}'>"
        f"<input name='severity' value='{html.escape(severity)}' placeholder='severity' size='10'>"
        f"<input name='kind' value='{html.escape(kind)}' placeholder='kind' size='10'>"
        "<button class='btn' type='submit'>Фильтр</button></form>"
        "<table><tr><th>#</th><th>severity</th><th>kind</th><th>code</th>"
        "<th>message</th><th>attrs</th></tr>" + event_rows + "</table>"
    )
    return _page(f"Отчёт {record.report_id[:8]}…", body)


@router.post("/reports/{report_id}/retry")
async def retry_report(request: Request, report_id: str) -> Response:
    ctx = request.app.state.context
    settings: Settings = ctx.settings
    guarded = _guard(request, settings, await _session(ctx, request))
    if isinstance(guarded, Response):
        return guarded
    db: Database = ctx.db
    form = dict(await request.form())
    if not _check_csrf(guarded, form):
        return _page("Ошибка", "<p class='bad'>Недействительный CSRF-токен.</p>")

    def _retry() -> bool:
        with db.transaction() as conn:
            ok = reports.retry_failed(conn, report_id)
            if ok:
                audit.write(
                    conn,
                    actor="admin",
                    action="report_retry",
                    target=report_id,
                    detail={"via": "admin-panel"},
                )
            return ok

    requeued = await db.run(_retry)
    message = "Отчёт возвращён в очередь." if requeued else "Повтор возможен только для FAILED."
    return _page("Повтор доставки", f"<p>{message}</p><p><a href='/admin/reports/{report_id}'>← к отчёту</a></p>")


@router.get("/reports/{report_id}/export.json")
async def export_report(request: Request, report_id: str) -> Response:
    ctx = request.app.state.context
    settings: Settings = ctx.settings
    guarded = _guard(request, settings, await _session(ctx, request))
    if isinstance(guarded, Response):
        return guarded
    db: Database = ctx.db

    record = await db.run(lambda: reports.get(db.connection, report_id))
    if record is None:
        return _not_found()

    # nonce_hash сознательно не экспортируется: это серверный секрет привязки.
    payload = {
        "report_id": record.report_id,
        "telegram_user_id": record.telegram_user_id,
        "status": record.status,
        "description": record.description,
        "summary": record.summary,
        "events": record.events(),
        "client_meta": record.client_meta(),
        "attempts": record.attempts,
        "max_attempts": record.max_attempts,
        "delivered_parts": record.delivered_parts,
        "last_error": record.last_error,
        "created_at": record.created_at,
        "delivered_at": record.delivered_at,
        "body_bytes": record.body_bytes,
        "app_version": record.app_version,
    }
    return JSONResponse(
        content=payload,
        headers={
            **_secure_headers(),
            "Content-Disposition": f"attachment; filename='report-{record.report_id}.json'",
        },
    )


# --- Тестировщики -----------------------------------------------------------


@router.get("/testers")
async def testers_page(request: Request, q: str = "", status: str = "all") -> Response:
    """Управление allowlist: изменения сразу видны bot-worker через общую SQLite."""
    ctx = request.app.state.context
    settings: Settings = ctx.settings
    guarded = _guard(request, settings, await _session(ctx, request))
    if isinstance(guarded, Response):
        return guarded
    db: Database = ctx.db

    entries = await db.run(lambda: allowlist.list_all(db.connection))
    active_count = sum(1 for entry in entries if entry.active)
    query = q.strip()[:80].casefold()
    selected = status if status in {"all", "active", "revoked"} else "all"
    filtered = [
        entry
        for entry in entries
        if (selected == "all" or (entry.active if selected == "active" else not entry.active))
        and (not query or query in str(entry.telegram_user_id) or query in entry.label.casefold())
    ]

    def _row(entry) -> str:
        status_label = (
            "<span class='status-pill active'>Активен</span>"
            if entry.active else "<span class='status-pill revoked'>Отозван</span>"
        )
        if entry.active:
            action = (
                "<form class='inline' method='post' action='/admin/testers/revoke'>"
                f"<input type='hidden' name='csrf' value='{guarded[1]}'>"
                f"<input type='hidden' name='user_id' value='{entry.telegram_user_id}'>"
                "<button class='btn danger' type='submit' title='Отозвать новые запросы и отменить ожидающие отчёты'>"
                "Отозвать</button></form>"
            )
        else:
            action = (
                "<form class='inline' method='post' action='/admin/testers/restore'>"
                f"<input type='hidden' name='csrf' value='{guarded[1]}'>"
                f"<input type='hidden' name='user_id' value='{entry.telegram_user_id}'>"
                "<button class='btn secondary' type='submit'>Разрешить снова</button></form>"
            )
        return (
            "<tr>"
            f"<td><code>{entry.telegram_user_id}</code></td><td>{status_label}</td>"
            f"<td>{html.escape(entry.label or '—')}</td>"
            f"<td>{_fmt_ts(entry.updated_at)}</td><td>{action}</td></tr>"
        )

    rows = "".join(_row(entry) for entry in filtered) or (
        "<tr><td colspan='5' class='empty-state'>Пользователи не найдены</td></tr>"
    )
    opts = "".join(
        f"<option value='{key}'{' selected' if key == selected else ''}>{label}</option>"
        for key, label in (
            ("all", "Все"), ("active", "Активные"), ("revoked", "Отозванные")
        )
    )
    body = (
        "<div class='notice success'><b>Без перезапуска бота.</b> "
        "Доступ хранится в SQLite и проверяется при каждой команде /report. "
        "Отзыв также аннулирует ожидающие nonce и отчёты.</div>"
        "<div class='kpi-strip'>"
        f"<div class='kpi'><b>{active_count}</b><span>Активных</span></div>"
        f"<div class='kpi'><b>{len(entries) - active_count}</b><span>Отозванных</span></div>"
        f"<div class='kpi'><b>{len(entries)}</b><span>Всего</span></div>"
        "</div>"
        "<h2>Разрешить отправку отчётов</h2>"
        "<form class='form-row' method='post' action='/admin/testers/add'>"
        f"<input type='hidden' name='csrf' value='{guarded[1]}'>"
        "<div class='field'><label for='new-id'>Telegram user ID</label>"
        "<input id='new-id' name='user_id' inputmode='numeric' "
        "placeholder='123456789' required pattern='[0-9]+' maxlength='20'></div>"
        "<div class='field'><label for='new-label'>Описание</label>"
        "<input id='new-label' name='label' maxlength='100' placeholder='Например, тестировщик'></div>"
        "<button class='btn' type='submit'>+ Добавить</button></form>"
        "<h2>Кто может отправлять отчёты</h2>"
        "<form class='toolbar' method='get' action='/admin/testers'>"
        "<div class='field search'><label for='tester-query'>Поиск по ID или описанию</label>"
        f"<input id='tester-query' name='q' value='{html.escape(q.strip()[:80], quote=True)}' "
        "placeholder='Поиск' maxlength='80'></div>"
        "<div class='field'><label for='tester-status'>Статус</label>"
        f"<select id='tester-status' name='status'>{opts}</select></div>"
        "<button class='btn secondary' type='submit'>Применить</button></form>"
        f"<p class='muted'>Показано: {len(filtered)} из {len(entries)}.</p>"
        "<div class='table-scroll'><table><thead><tr>"
        "<th>User ID</th><th>Статус</th><th>Описание</th><th>Изменён</th><th>Действие</th>"
        f"</tr></thead><tbody>{rows}</tbody></table></div>"
    )
    return _page("Доступ к отчётам", body)


@router.post("/testers/add")
async def testers_add(request: Request) -> Response:
    ctx = request.app.state.context
    settings: Settings = ctx.settings
    guarded = _guard(request, settings, await _session(ctx, request))
    if isinstance(guarded, Response):
        return guarded
    db: Database = ctx.db
    form = dict(await request.form())
    if not _check_csrf(guarded, form):
        return _page("Ошибка", "<p class='bad'>Недействительный CSRF-токен.</p>")
    raw_id = form.get("user_id")
    user_id = _telegram_user_id(raw_id)
    if user_id is None:
        return _page("Ошибка", "<p class='bad'>Некорректный user id.</p>")
    label = form.get("label")
    label = label.strip()[:100] if isinstance(label, str) else ""

    def _add() -> None:
        with db.transaction() as conn:
            allowlist.add(conn, user_id, label=label)
            audit.write(
                conn,
                actor="admin",
                action="allowlist_add",
                target=raw_id,
                detail={"label": label, "via": "admin-panel"},
            )

    await db.run(_add)
    return RedirectResponse("/admin/testers", status_code=303)


@router.post("/testers/restore")
async def testers_restore(request: Request) -> Response:
    """Повторно разрешает ранее отозванному пользователю присылать отчёты."""
    ctx = request.app.state.context
    guarded = _guard(request, ctx.settings, await _session(ctx, request))
    if isinstance(guarded, Response):
        return guarded
    form = dict(await request.form())
    if not _check_csrf(guarded, form):
        return _page("Ошибка", "<p class='bad'>Недействительный CSRF-токен.</p>")
    raw_id = form.get("user_id")
    user_id = _telegram_user_id(raw_id)
    if user_id is None:
        return _page("Ошибка", "<p class='bad'>Некорректный user id.</p>")
    db: Database = ctx.db

    def _restore() -> bool:
        with db.transaction() as conn:
            existing = allowlist.get(conn, user_id)
            if existing is None or existing.active:
                return False
            allowlist.add(conn, user_id, label=existing.label)
            audit.write(
                conn,
                actor="admin",
                action="allowlist_restore",
                target=str(user_id),
                detail={"via": "admin-panel"},
            )
            return True

    restored = await db.run(_restore)
    if not restored:
        return _page("Ошибка", "<p class='bad'>Запись не найдена или уже активна.</p>")
    return RedirectResponse("/admin/testers", status_code=303)


@router.post("/testers/revoke")
async def testers_revoke(request: Request) -> Response:
    ctx = request.app.state.context
    settings: Settings = ctx.settings
    guarded = _guard(request, settings, await _session(ctx, request))
    if isinstance(guarded, Response):
        return guarded
    db: Database = ctx.db
    form = dict(await request.form())
    if not _check_csrf(guarded, form):
        return _page("Ошибка", "<p class='bad'>Недействительный CSRF-токен.</p>")
    raw_id = form.get("user_id")
    user_id = _telegram_user_id(raw_id)
    if user_id is None:
        return _page("Ошибка", "<p class='bad'>Некорректный user id.</p>")

    def _revoke() -> dict[str, int]:
        with db.transaction() as conn:
            changed = allowlist.revoke(conn, user_id, reason="revoked via admin panel")
            revoked_nonces = nonces.revoke_for_user(conn, user_id)
            dropped = reports.drop_pending_for_user(conn, user_id, reason="allowlist revoked")
            audit.write(
                conn,
                actor="admin",
                action="allowlist_remove",
                target=raw_id,
                detail={
                    "was_active": changed,
                    "revoked_nonces": revoked_nonces,
                    "dropped_reports": dropped,
                    "via": "admin-panel",
                },
            )
            return {"revoked_nonces": revoked_nonces, "dropped_reports": dropped}

    stats = await db.run(_revoke)
    log.info("allowlist revoked via admin panel", extra={"user_id": user_id, **stats})
    return RedirectResponse("/admin/testers", status_code=303)


# --- Выключатель приёма -----------------------------------------------------


@router.post("/intake")
async def intake_toggle(request: Request) -> Response:
    ctx = request.app.state.context
    settings: Settings = ctx.settings
    guarded = _guard(request, settings, await _session(ctx, request))
    if isinstance(guarded, Response):
        return guarded
    db: Database = ctx.db
    form = dict(await request.form())
    if not _check_csrf(guarded, form):
        return _page("Ошибка", "<p class='bad'>Недействительный CSRF-токен.</p>")
    action = form.get("action")
    if action not in {"on", "off"}:
        return _page("Ошибка", "<p class='bad'>Некорректное действие.</p>")

    def _toggle() -> None:
        with db.transaction() as conn:
            set_intake_enabled(
                conn,
                action == "on",
                actor="admin",
                note="toggled via admin panel",
            )

    await db.run(_toggle)
    return RedirectResponse("/admin", status_code=303)


# --- Аудит ------------------------------------------------------------------


@router.get("/audit")
async def audit_page(request: Request) -> Response:
    ctx = request.app.state.context
    settings: Settings = ctx.settings
    guarded = _guard(request, settings, await _session(ctx, request))
    if isinstance(guarded, Response):
        return guarded
    db: Database = ctx.db

    def _load():
        with db.transaction() as conn:
            return audit.recent(conn, limit=100)

    entries = await db.run(_load)
    rows = "".join(
        "<tr>"
        f"<td>{_fmt_ts(entry.at)}</td>"
        f"<td>{html.escape(entry.actor)}</td>"
        f"<td>{html.escape(entry.action)}</td>"
        f"<td>{html.escape(entry.target or '—')}</td>"
        f"<td>{html.escape(json.dumps(entry.detail, ensure_ascii=False)) if entry.detail else '—'}</td>"
        "</tr>"
        for entry in entries
    ) or "<tr><td colspan='5' class='muted'>пусто</td></tr>"

    body = (
        "<table><tr><th>время</th><th>actor</th><th>действие</th><th>объект</th>"
        f"<th>детали</th></tr>{rows}</table>"
    )
    return _page("Аудит", body)


__all__ = ["router"]
