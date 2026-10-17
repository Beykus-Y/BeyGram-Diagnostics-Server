"""Интеграционные тесты HTTP API приёма отчётов.

Проверяют сквозные гарантии: подтверждение через бота, идемпотентность,
запрет повторного использования токена, лимиты, отзыв доступа, отсутствие
доверия к полям клиента.
"""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.repository import allowlist, nonces
from app.security import hash_nonce


@pytest.fixture()
def client(settings):
    app = create_app(settings)
    with TestClient(app) as c:
        yield c


def _issue_nonce(client: TestClient, settings, user_id: int = 555001) -> str:
    """Прогоняет «бот подтвердил nonce» и возвращает сырой nonce."""
    from app.security import generate_nonce

    nonce = generate_nonce()
    ctx = client.app.state.context

    with ctx.db.transaction() as conn:
        allowlist.add(conn, user_id, label="tester")
        nonces.register_issued(
            conn,
            nonce_hash=hash_nonce(settings.nonce_pepper, nonce),
            telegram_user_id=user_id,
            ttl_seconds=settings.nonce_ttl_seconds,
        )
    return nonce


def _report_body(report_id: str | None = None, description: str = "Не подключается VPN") -> dict:
    return {
        "schema_version": 1,
        "report_id": report_id or str(uuid.uuid4()),
        "description": description,
        "client_meta": {"app_version": "1.2.3", "platform": "android", "vpn_active": True},
        "events": [
            {
                "seq": 1,
                "at": 1700000000.0,
                "kind": "vpn",
                "severity": "error",
                "code": "VPN_CONNECT_TIMEOUT",
                "message": "timeout after 30s",
                "attrs": {"latency_ms": "30000", "password": "should-be-removed"},
            }
        ],
    }


def _post(client, nonce, body):
    return client.post(
        "/api/v1/bug-reports",
        headers={"Authorization": f"Bearer {nonce}", "Content-Type": "application/json"},
        content=json.dumps(body).encode("utf-8"),
    )


# --- Успешный поток ---------------------------------------------------------


def test_successful_report_accepted(client, settings):
    nonce = _issue_nonce(client, settings)
    body = _report_body()
    response = _post(client, nonce, body)

    assert response.status_code == 202, response.text
    data = response.json()
    assert data["report_id"] == body["report_id"]
    assert data["status"] == "queued"
    assert data["status_token"]
    assert data["idempotent_replay"] is False


def test_sensitive_attribute_is_redacted(client, settings):
    nonce = _issue_nonce(client, settings)
    body = _report_body()
    response = _post(client, nonce, body)
    assert response.status_code == 202

    ctx = client.app.state.context
    with ctx.db.transaction() as conn:
        row = conn.execute(
            "SELECT events_json FROM reports WHERE report_id = ?", (body["report_id"],)
        ).fetchone()
    events = json.loads(row["events_json"])
    assert events[0]["attrs"]["password"] == "[redacted]"
    assert events[0]["attrs"]["latency_ms"] == "30000"


# --- Идемпотентность и повторное использование ------------------------------


def test_same_report_id_same_content_is_idempotent(client, settings):
    nonce = _issue_nonce(client, settings)
    body = _report_body()

    first = _post(client, nonce, body)
    second = _post(client, nonce, body)

    assert first.status_code == 202
    assert second.status_code == 202, second.text
    assert second.json()["idempotent_replay"] is True
    assert second.json()["report_id"] == first.json()["report_id"]

    ctx = client.app.state.context
    with ctx.db.transaction() as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM reports").fetchone()["c"]
    assert count == 1, "повтор не должен создавать дубль"


def test_nonce_cannot_be_used_for_another_report_id(client, settings):
    nonce = _issue_nonce(client, settings)
    first = _post(client, nonce, _report_body())
    assert first.status_code == 202

    other = _report_body()  # новый report_id, тот же nonce
    second = _post(client, nonce, other)
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "report_conflict"


def test_same_report_id_different_content_conflicts(client, settings):
    nonce = _issue_nonce(client, settings)
    body = _report_body()
    assert _post(client, nonce, body).status_code == 202

    changed = dict(body)
    changed["description"] = "Другое описание проблемы"
    response = _post(client, nonce, changed)
    assert response.status_code == 409


# --- Аутентификация ---------------------------------------------------------


def test_unknown_nonce_rejected(client):
    response = _post(client, "A" * 43, _report_body())
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_token"


def test_malformed_nonce_rejected(client):
    response = _post(client, "not-a-valid-nonce", _report_body())
    assert response.status_code == 401


def test_missing_authorization_rejected(client):
    response = client.post("/api/v1/bug-reports", json=_report_body())
    assert response.status_code == 401


def test_client_cannot_forge_telegram_user_id(client, settings):
    """Поля telegram_user_id/nonce в теле не принимаются схемой."""
    nonce = _issue_nonce(client, settings, user_id=555001)
    body = _report_body()
    body["telegram_user_id"] = 1  # попытка подмены
    response = _post(client, nonce, body)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "payload_invalid"


def test_revoked_user_cannot_submit(client, settings):
    nonce = _issue_nonce(client, settings, user_id=555002)
    ctx = client.app.state.context
    with ctx.db.transaction() as conn:
        allowlist.revoke(conn, 555002, reason="test")

    response = _post(client, nonce, _report_body())
    assert response.status_code == 401


# --- Лимиты -----------------------------------------------------------------


def test_per_user_window_limit(client, settings):
    """<= 2 отчёта за 10 минут: третий должен получить 429."""
    user_id = 555003
    accepted = 0
    for _ in range(3):
        nonce = _issue_nonce(client, settings, user_id=user_id)
        response = _post(client, nonce, _report_body())
        if response.status_code == 202:
            accepted += 1

    assert accepted == settings.rl_user_reports_per_window

    # Ещё одна попытка — точно лимит.
    nonce = _issue_nonce(client, settings, user_id=user_id)
    response = _post(client, nonce, _report_body())
    assert response.status_code == 429
    assert "Retry-After" in response.headers


# --- Валидация схемы --------------------------------------------------------


def test_description_too_long_rejected(client, settings):
    nonce = _issue_nonce(client, settings)
    body = _report_body(description="x" * 2001)
    response = _post(client, nonce, body)
    assert response.status_code == 422


def test_body_too_large_rejected(client, settings):
    nonce = _issue_nonce(client, settings)
    body = _report_body()
    # Раздуваем событиями сверх лимита тела.
    body["events"] = [
        {"kind": "other", "message": "y" * 500, "attrs": {}} for _ in range(1000)
    ]
    response = _post(client, nonce, body)
    assert response.status_code == 413


def test_invalid_report_id_rejected(client, settings):
    nonce = _issue_nonce(client, settings)
    body = _report_body(report_id="not-a-uuid")
    response = _post(client, nonce, body)
    assert response.status_code == 422


def test_extra_fields_rejected(client, settings):
    nonce = _issue_nonce(client, settings)
    body = _report_body()
    body["arbitrary_blob"] = "base64..."  # схема запрещает лишние поля
    response = _post(client, nonce, body)
    assert response.status_code == 422


# --- Статус -----------------------------------------------------------------


def test_status_lookup_with_token(client, settings):
    nonce = _issue_nonce(client, settings)
    body = _report_body()
    accepted = _post(client, nonce, body).json()

    response = client.get(
        f"/api/v1/bug-reports/{accepted['report_id']}",
        headers={"Authorization": f"Bearer {accepted['status_token']}"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "queued"


def test_status_lookup_with_wrong_token(client, settings):
    nonce = _issue_nonce(client, settings)
    body = _report_body()
    accepted = _post(client, nonce, body).json()

    response = client.get(
        f"/api/v1/bug-reports/{accepted['report_id']}",
        headers={"Authorization": "Bearer " + "Z" * 32},
    )
    assert response.status_code == 401


def test_status_token_in_query_string_rejected(client, settings):
    """Токен статуса не принимается через URL (логи прокси/история браузера)."""
    nonce = _issue_nonce(client, settings)
    accepted = _post(client, nonce, _report_body()).json()

    response = client.get(
        f"/api/v1/bug-reports/{accepted['report_id']}?status_token={accepted['status_token']}"
    )
    assert response.status_code == 401


def test_dropped_report_shows_cancelled_status(client, settings):
    """После отзыва доступа клиент видит терминальный cancelled, не queued."""
    nonce = _issue_nonce(client, settings, user_id=555004)
    accepted = _post(client, nonce, _report_body()).json()

    ctx = client.app.state.context
    with ctx.db.transaction() as conn:
        allowlist.revoke(conn, 555004, reason="left beta")
        from app.repository import reports

        reports.drop_pending_for_user(conn, 555004, reason="allowlist revoked")

    status = client.get(
        f"/api/v1/bug-reports/{accepted['report_id']}",
        headers={"Authorization": f"Bearer {accepted['status_token']}"},
    )
    assert status.status_code == 200
    assert status.json()["status"] == "cancelled"

    # Отозванный пользователь больше не может пользоваться и токеном отчёта.
    replay = _post(client, nonce, _report_body())
    assert replay.status_code == 401


def test_unsanitized_fields_are_redacted_everywhere(client, settings):
    """code, имена attrs и client_meta проходят санитизацию (#1)."""
    nonce = _issue_nonce(client, settings)
    body = _report_body()
    body["events"][0]["code"] = "leak token=very_secret_value_123456"
    body["events"][0]["attrs"] = {
        "secret_host": "vless://user@hidden.example:443",
        "endpoint": "proxy 2001:db8::1 deadbeef.example",
    }
    body["client_meta"]["device_model"] = "vless://user@secret.example"
    assert _post(client, nonce, body).status_code == 202

    ctx = client.app.state.context
    with ctx.db.transaction() as conn:
        row = conn.execute(
            "SELECT events_json, client_meta_json FROM reports WHERE report_id = ?",
            (body["report_id"],),
        ).fetchone()
    events = json.loads(row["events_json"])
    meta = json.loads(row["client_meta_json"])

    assert "very_secret_value" not in events[0]["code"]
    assert "hidden.example" not in json.dumps(events[0]["attrs"])
    assert "2001:db8::1" not in json.dumps(events[0]["attrs"])
    assert "deadbeef.example" not in json.dumps(events[0]["attrs"])
    assert "secret.example" not in meta["device_model"]


def test_health(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
