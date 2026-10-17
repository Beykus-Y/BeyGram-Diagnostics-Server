"""Тесты административной веб-панели: доступ, CSRF, действия, экспорт."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.repository import allowlist, reports

ADMIN_TOKEN = "test-admin-token-0123456789"


@pytest.fixture()
def admin_settings(settings):
    settings.admin_token = ADMIN_TOKEN
    return settings


@pytest.fixture()
def client(admin_settings):
    app = create_app(admin_settings)
    with TestClient(app) as c:
        yield c


def _login(client) -> None:
    response = client.post("/admin/login", data={"token": ADMIN_TOKEN}, follow_redirects=False)
    assert response.status_code == 303
    assert "admin_session" in client.cookies


def _csrf(client) -> str:
    page = client.get("/admin").text
    match = re.search(r"name='csrf' value='([^']+)'", page)
    assert match, "csrf-токен должен присутствовать в формах"
    return match.group(1)


def _seed_failed_report(client, settings) -> str:
    """Создаёт FAILED-отчёт напрямую в БД."""
    from tests.test_delivery_worker import _seed_report

    report_id = _seed_report(client.app.state.context.db, settings)
    with client.app.state.context.db.transaction() as conn:
        conn.execute("UPDATE reports SET status='FAILED', last_error='permanent: x' WHERE report_id=?", (report_id,))
    return report_id


# --- Доступ -----------------------------------------------------------------


def test_panel_disabled_returns_404(settings):
    settings.admin_token = ""
    app = create_app(settings)
    with TestClient(app) as c:
        assert c.get("/admin").status_code == 404
        assert c.get("/admin/login").status_code == 404
        assert c.post("/admin/login", data={"token": "x"}).status_code == 404


def test_unauthenticated_redirects_to_login(client):
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 303
    assert "/admin/login" in response.headers["location"]


def test_login_wrong_token_rejected(client):
    response = client.post("/admin/login", data={"token": "wrong-token"})
    assert response.status_code == 401
    assert "admin_session" not in client.cookies


def test_login_success_sets_session_cookie(client):
    _login(client)
    assert "admin_session" in client.cookies
    page = client.get("/admin")
    assert page.status_code == 200
    # Заголовки безопасности на месте.
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["x-frame-options"] == "DENY"


def test_login_rate_limited(client, settings):
    for _ in range(settings.admin_login_attempts_per_hour):
        client.post("/admin/login", data={"token": "wrong"})
    response = client.post("/admin/login", data={"token": "wrong"})
    assert "Слишком много" in response.text


# --- CSRF -------------------------------------------------------------------


def test_write_without_csrf_rejected(client):
    _login(client)
    response = client.post("/admin/intake", data={"action": "off"})
    assert "CSRF" in response.text


def test_intake_toggle_via_panel(client, admin_settings):
    _login(client)
    token = _csrf(client)

    response = client.post(
        "/admin/intake",
        data={"csrf": token, "action": "off"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    ctx = client.app.state.context
    with ctx.db.transaction() as conn:
        assert intake_enabled_value(conn, admin_settings) is False

    # И обратно.
    client.post("/admin/intake", data={"csrf": token, "action": "on"})
    with ctx.db.transaction() as conn:
        assert intake_enabled_value(conn, admin_settings) is True


def intake_enabled_value(conn, settings) -> bool:
    from app.services.settings_service import intake_enabled

    return intake_enabled(conn, settings)


# --- Отчёты -----------------------------------------------------------------


def test_reports_list_and_detail(client):
    _login(client)
    report_id = _seed_failed_report(client, client.app.state.context.settings)

    listing = client.get("/admin/reports")
    assert listing.status_code == 200
    assert report_id[:8] in listing.text

    detail = client.get(f"/admin/reports/{report_id}")
    assert detail.status_code == 200
    assert "Повторить доставку" in detail.text


def test_retry_only_from_failed(client, admin_settings):
    _login(client)
    report_id = _seed_failed_report(client, admin_settings)
    token = _csrf(client)

    response = client.post(f"/admin/reports/{report_id}/retry", data={"csrf": token})
    assert "возвращён в очередь" in response.text

    ctx = client.app.state.context
    with ctx.db.transaction() as conn:
        assert reports.get(conn, report_id).status == "QUEUED"

    # Повторный retry для не-FAILED отклоняется.
    response = client.post(f"/admin/reports/{report_id}/retry", data={"csrf": token})
    assert "только для FAILED" in response.text


def test_export_json_excludes_secrets(client, admin_settings):
    _login(client)
    report_id = _seed_failed_report(client, admin_settings)

    response = client.get(f"/admin/reports/{report_id}/export.json")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    data = response.json()
    assert data["report_id"] == report_id
    assert "nonce_hash" not in data, "серверная привязка nonce не экспортируется"


# --- Тестировщики -----------------------------------------------------------


def test_testers_add_and_revoke_via_panel(client):
    _login(client)
    token = _csrf(client)

    response = client.post(
        "/admin/testers/add",
        data={"csrf": token, "user_id": "777333", "label": "from panel"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    ctx = client.app.state.context
    with ctx.db.transaction() as conn:
        assert allowlist.is_active(conn, 777333)

    response = client.post(
        "/admin/testers/revoke",
        data={"csrf": token, "user_id": "777333"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    with ctx.db.transaction() as conn:
        assert not allowlist.is_active(conn, 777333)


def test_testers_invalid_user_id_rejected(client):
    _login(client)
    token = _csrf(client)
    response = client.post("/admin/testers/add", data={"csrf": token, "user_id": "abc"})
    assert "Некорректный" in response.text


# --- Аудит и обзор ----------------------------------------------------------


def test_audit_page_shows_admin_actions(client):
    _login(client)
    token = _csrf(client)
    client.post("/admin/intake", data={"csrf": token, "action": "off"})

    page = client.get("/admin/audit")
    assert page.status_code == 200
    assert "intake_disabled" in page.text


def test_overview_shows_workers_and_intake(client):
    _login(client)
    page = client.get("/admin")
    assert page.status_code == 200
    assert "Приём отчётов" in page.text
    assert "Фоновые воркеры" in page.text


def test_malformed_session_cookie_redirects(client):
    client.cookies.set("admin_session", "garbage-value")
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 303


def test_changing_admin_token_revokes_sessions(client, admin_settings):
    """Смена ADMIN_TOKEN инвалидирует выданные ранее сессии (#15)."""
    _login(client)
    assert client.get("/admin", follow_redirects=False).status_code == 200

    # «Смена» токена в тех же настройках (тот же процесс, тот же pepper).
    admin_settings.admin_token = "rotated-admin-token-9876543210"

    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 303, "старая сессия должна стать недействительной"

    # Повторный вход уже с новым токеном работает.
    response = client.post(
        "/admin/login",
        data={"token": "rotated-admin-token-9876543210"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert client.get("/admin", follow_redirects=False).status_code == 200


def test_old_csrf_invalid_after_token_rotation(client, admin_settings):
    """CSRF-токены, выданные до смены ADMIN_TOKEN, тоже отклоняются."""
    _login(client)
    old_csrf = _csrf(client)

    admin_settings.admin_token = "rotated-admin-token-9876543210"
    client.post(
        "/admin/login",
        data={"token": "rotated-admin-token-9876543210"},
        follow_redirects=False,
    )
    response = client.post("/admin/intake", data={"csrf": old_csrf, "action": "off"})
    assert "CSRF" in response.text


# --- Серверный реестр сессий (#18) ------------------------------------------


def _cookie_value(client) -> str:
    value = client.cookies.get("admin_session")
    assert value, "после логина cookie должна существовать"
    return value


def test_each_login_creates_unique_session(client):
    """Сессии, созданные в одну секунду, имеют разные cookie (#18)."""
    first = _cookie_value_after_login(client)
    second = _cookie_value_after_login(client)
    assert first != second, "cookie сессии должны быть уникальны"


def _cookie_value_after_login(client) -> str:
    client.post("/admin/login", data={"token": ADMIN_TOKEN}, follow_redirects=False)
    return _cookie_value(client)


def test_logout_revokes_session_server_side(client):
    """Сохранённая копия cookie после logout недействительна (#18)."""
    _login(client)
    saved_cookie = _cookie_value(client)

    client.post("/admin/logout", follow_redirects=False)
    assert "admin_session" not in client.cookies

    # Воспроизводим сохранённую копию cookie: доступ должен быть закрыт.
    client.cookies.set("admin_session", saved_cookie)
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 303, "отозванная сессия не должна работать"


def test_replayed_cookie_without_logout_still_works(client):
    """Без logout сохранённая cookie работает (регрессия на #18)."""
    _login(client)
    saved_cookie = _cookie_value(client)

    client.cookies.clear()
    client.cookies.set("admin_session", saved_cookie)
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 200


def test_expired_session_pruned_from_registry(db, admin_settings):
    """prune_expired удаляет просроченные записи; read_session их отвергает."""
    from app import admin_sessions

    with db.transaction() as conn:
        cookie, _ = admin_sessions.create_session(conn, admin_settings)
        # Сессия ещё жива — читается.
        assert admin_sessions.read_session(conn, admin_settings, cookie) is not None

    with db.transaction() as conn:
        # Симулируем прошедший срок.
        conn.execute("UPDATE kv SET value = '1' WHERE key LIKE 'admin_session:%'")
        assert admin_sessions.read_session(conn, admin_settings, cookie) is None
        removed = admin_sessions.prune_expired(conn)
        assert removed == 1
        # Повторная чистка — нечего удалять.
        assert admin_sessions.prune_expired(conn) == 0


def test_maintenance_prunes_sessions(db, settings):
    """maintenance._tick подчищает просроченные админ-сессии."""
    import asyncio

    from app import admin_sessions
    from app.services import maintenance

    class FakeCtx:
        def __init__(self, db, settings):
            self.db = db
            self.settings = settings
            import asyncio

            self.stopping = asyncio.Event()

        def worker_success(self, name):  # noqa: ARG002
            pass

        def worker_failure(self, name, error):  # noqa: ARG002
            pass

    with db.transaction() as conn:
        admin_sessions.create_session(conn, settings)
        conn.execute("UPDATE kv SET value = '1' WHERE key LIKE 'admin_session:%'")

    ctx = FakeCtx(db, settings)
    asyncio.run(maintenance._tick(ctx, settings, last_checkpoint=0.0))

    with db.transaction() as conn:
        remaining = conn.execute(
            "SELECT COUNT(*) AS c FROM kv WHERE key LIKE 'admin_session:%'"
        ).fetchone()
    assert remaining["c"] == 0
