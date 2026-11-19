"""BG Push: API, привязка PWA, приём Telegram-пушей, воркер, admin и PWA-страницы.

Крипто-цепочка проверяется целиком: Telegram-подобный payload шифруется под ingress-ключ,
сервер оборачивает его во внешний Web Push-слой, а тест расшифровывает оба слоя как браузер.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.push import crypto, service, worker
from app.push.crypto import (
    decrypt_aes128gcm,
    encrypt_aes128gcm,
    generate_vapid_pem,
    verify_vapid_authorization,
)
from app.util import b64url_encode

ADMIN_TOKEN = "test-admin-token-0123456789"


def _token() -> str:
    return b64url_encode(secrets.token_bytes(32))


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def push_settings(tmp_path) -> Settings:
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "vapid_private.pem").write_bytes(generate_vapid_pem())
    (keys / "storage.key").write_text(b64url_encode(os.urandom(32)) + "\n")
    return Settings(
        app_env="test",
        log_level="WARNING",
        log_format="text",
        database_path=str(tmp_path / "reports.db"),
        nonce_pepper="test-pepper-that-is-long-enough-for-hmac-0123456789",
        report_bot_token="",
        delivery_bot_token="",
        delivery_chat_id=0,
        require_https=False,
        enable_bot=False,
        enable_worker=False,
        enable_maintenance=False,
        bootstrap_allowlist="",
        enable_push=True,
        push_database_path=str(tmp_path / "push.db"),
        push_public_base_url="https://push.test",
        push_vapid_private_key_file=str(keys / "vapid_private.pem"),
        push_vapid_subject="mailto:push@test.example",
        push_storage_key_file=str(keys / "storage.key"),
    )


class Browser:
    """Имитация PWA на устройстве: ключи подписки Web Push и ключи ingress, которых сервер не знает."""

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.p256dh = crypto.public_key_bytes(self.key.public_key())
        self.auth = os.urandom(16)
        self.ingress_key = ec.generate_private_key(ec.SECP256R1())
        self.ingress_pub = crypto.public_key_bytes(self.ingress_key.public_key())
        self.ingress_auth = os.urandom(16)

    def complete_payload(self, endpoint: str = "https://web.push.apple.com/QWxhZGRpbjpvcGVu") -> dict:
        return {
            "endpoint": endpoint,
            "keys": {"p256dh": b64url_encode(self.p256dh), "auth": b64url_encode(self.auth)},
            "ingress": {"p256dh": b64url_encode(self.ingress_pub), "auth": b64url_encode(self.ingress_auth)},
            "platform": "ios_pwa",
        }

    def open_outer(self, body: bytes) -> bytes:
        return decrypt_aes128gcm(body, private_key=self.key, auth_secret=self.auth)

    def open_inner(self, body: bytes) -> bytes:
        return decrypt_aes128gcm(body, private_key=self.ingress_key, auth_secret=self.ingress_auth)


def _pair(client: TestClient, browser: Browser | None = None) -> dict:
    """Полный цикл привязки: нативный клиент создаёт регистрацию, PWA завершает её."""
    browser = browser or Browser()
    owner = _token()
    created = client.post("/api/v1/push/registrations", headers=_auth(owner))
    assert created.status_code == 201, created.text
    body = created.json()
    rid = body["registration_id"]
    secret = body["pairing_code"].split(".")[2]
    done = client.post(
        f"/api/v1/push/registrations/{rid}/complete",
        headers=_auth(secret),
        json=browser.complete_payload(),
    )
    assert done.status_code == 200, done.text
    return {
        "owner": owner,
        "rid": rid,
        "token": done.json()["token"],
        "ingress_url": body["ingress_url"],
        "capability": body["ingress_url"].rsplit("/", 1)[1],
        "browser": browser,
    }


def _ingress(client: TestClient, pair: dict, plaintext: bytes, *, ttl: str = "600") -> httpx.Response:
    body = encrypt_aes128gcm(
        plaintext, ua_public=pair["browser"].ingress_pub, auth_secret=pair["browser"].ingress_auth
    )
    return client.post(
        f"/api/v1/push/ingress/{pair['capability']}",
        content=body,
        headers={"Content-Encoding": "aes128gcm", "TTL": ttl},
    )


def _run_worker(client: TestClient, handler, *, at: float | None = None) -> int:
    ctx = client.app.state.context

    async def _go() -> int:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            return await worker.process_once(ctx, http, at=at)

    return client.portal.call(_go)


# --- Выключенный модуль ------------------------------------------------------


def test_disabled_module_hides_api_and_pwa(tmp_path):
    settings = Settings(
        app_env="test",
        require_https=False,
        enable_bot=False,
        enable_worker=False,
        enable_maintenance=False,
        database_path=str(tmp_path / "r.db"),
        nonce_pepper="x" * 40,
        report_bot_token="",
        bootstrap_allowlist="",
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/push/config").json() == {"enabled": False}
        assert client.post("/api/v1/push/registrations", headers=_auth(_token())).status_code == 503
        assert client.get("/push/").status_code == 404
        assert "push" not in client.get("/readyz").json() or client.get("/readyz").json()["push"] is None


# --- Привязка ----------------------------------------------------------------


def test_pairing_activates_once_and_keeps_secrets_private(push_settings):
    browser = Browser()
    with TestClient(create_app(push_settings)) as client:
        owner = _token()
        created = client.post("/api/v1/push/registrations", headers=_auth(owner))
        assert created.status_code == 201
        body = created.json()
        rid = body["registration_id"]
        assert body["state"] == "pending"
        assert body["ingress_url"].startswith("https://push.test/api/v1/push/ingress/")
        assert body["setup_url"] == f"https://push.test/push/setup#{body['pairing_code']}"
        secret = body["pairing_code"].split(".")[2]

        assert client.get("/api/v1/push/config").json()["vapid_public_key"]
        assert client.post(
            f"/api/v1/push/registrations/{rid}/complete", headers=_auth(_token()), json=browser.complete_payload()
        ).status_code == 401
        bad_host = browser.complete_payload("https://evil.example/x")
        assert client.post(
            f"/api/v1/push/registrations/{rid}/complete", headers=_auth(secret), json=bad_host
        ).status_code == 422

        done = client.post(
            f"/api/v1/push/registrations/{rid}/complete", headers=_auth(secret), json=browser.complete_payload()
        )
        assert done.status_code == 200, done.text
        assert done.headers["cache-control"] == "no-store"
        token = done.json()["token"]
        assert client.post(
            f"/api/v1/push/registrations/{rid}/complete", headers=_auth(secret), json=browser.complete_payload()
        ).status_code == 401, "одноразовый секрет нельзя использовать повторно"

        owner_view = client.get(f"/api/v1/push/registrations/{rid}", headers=_auth(owner)).json()
        assert owner_view["state"] == "active"
        assert owner_view["telegram_keys"] == {
            "p256dh": b64url_encode(browser.ingress_pub),
            "auth": b64url_encode(browser.ingress_auth),
        }
        device_view = client.get(f"/api/v1/push/registrations/{rid}", headers=_auth(token)).json()
        assert device_view["state"] == "active"
        assert "telegram_keys" not in device_view
        assert client.get(f"/api/v1/push/registrations/{rid}", headers=_auth(_token())).status_code == 401

        assert client.post(f"/api/v1/push/registrations/{rid}/telegram-confirm", headers=_auth(token)).status_code == 401
        confirmed = client.post(f"/api/v1/push/registrations/{rid}/telegram-confirm", headers=_auth(owner))
        assert confirmed.json()["ok"] is True

        # В базе нет открытого адреса подписки и ключей: только шифртекст.
        row = client.app.state.context.push_db.connection.execute(
            "SELECT endpoint_sealed, endpoint_host, auth_sealed FROM push_registrations WHERE registration_id = ?",
            (rid,),
        ).fetchone()
        assert "web.push.apple.com" not in row["endpoint_sealed"]
        assert row["endpoint_host"] == "web.push.apple.com"
        assert b64url_encode(browser.auth) not in row["auth_sealed"]


def test_pairing_attempts_are_rate_limited_even_when_rejected(push_settings):
    settings = push_settings.model_copy(update={"rl_push_complete_per_15m": 2})
    with TestClient(create_app(settings)) as client:
        rid = client.post("/api/v1/push/registrations", headers=_auth(_token())).json()["registration_id"]
        statuses = [
            client.post(
                f"/api/v1/push/registrations/{rid}/complete", headers=_auth(_token()), json=Browser().complete_payload()
            ).status_code
            for _ in range(3)
        ]
        assert statuses == [401, 401, 429], "неудачные попытки должны считаться, а не откатываться"


def test_expired_pairing_cannot_be_completed(push_settings):
    settings = push_settings.model_copy(update={"push_pairing_ttl_seconds": 60})
    with TestClient(create_app(settings)) as client:
        created = client.post("/api/v1/push/registrations", headers=_auth(_token())).json()
        ctx = client.app.state.context
        ctx.push_db.connection.execute(
            "UPDATE push_registrations SET pairing_expires_at = ? WHERE registration_id = ?",
            (time.time() - 1, created["registration_id"]),
        )
        secret = created["pairing_code"].split(".")[2]
        response = client.post(
            f"/api/v1/push/registrations/{created['registration_id']}/complete",
            headers=_auth(secret),
            json=Browser().complete_payload(),
        )
        assert response.status_code == 401


# --- Приём Telegram-пушей ----------------------------------------------------


def test_ingress_accepts_only_known_capability_and_bounded_aes128gcm(push_settings):
    with TestClient(create_app(push_settings)) as client:
        pair = _pair(client)
        path = f"/api/v1/push/ingress/{pair['capability']}"
        assert _ingress(client, pair, b'{"type":"message"}').status_code == 201

        unknown = client.post(
            "/api/v1/push/ingress/" + "A" * 43, content=b"x" * 40, headers={"Content-Encoding": "aes128gcm"}
        )
        assert unknown.status_code == 404
        assert client.post(path, content=b"x" * 40, headers={"Content-Encoding": "aesgcm"}).status_code == 415
        assert client.post(path, content=b"", headers={"Content-Encoding": "aes128gcm"}).status_code == 422
        too_big = client.post(path, content=b"x" * 3901, headers={"Content-Encoding": "aes128gcm"})
        assert too_big.status_code == 413

        assert client.delete(f"/api/v1/push/registrations/{pair['rid']}", headers=_auth(pair["owner"])).status_code == 200
        assert _ingress(client, pair, b"after revoke").status_code == 404


def test_queue_limits_and_kill_switches(push_settings):
    settings = push_settings.model_copy(update={"push_queue_max_per_registration": 2})
    with TestClient(create_app(settings)) as client:
        pair = _pair(client)
        assert _ingress(client, pair, b"one").status_code == 201
        assert _ingress(client, pair, b"two").status_code == 201
        full = _ingress(client, pair, b"three")
        assert full.status_code == 503
        assert full.json()["error"]["code"] == "queue_full"

        ctx = client.app.state.context
        with ctx.push_db.transaction() as conn:
            service.set_switch(conn, service.SWITCH_INGRESS, False)
        assert _ingress(client, pair, b"four").json()["error"]["code"] == "ingress_disabled"
        with ctx.push_db.transaction() as conn:
            service.set_switch(conn, service.SWITCH_INGRESS, True)
            service.set_switch(conn, service.SWITCH_OUTBOUND, False)
        calls: list[httpx.Request] = []
        assert _run_worker(client, lambda r: calls.append(r) or httpx.Response(201)) == 0
        assert calls == [], "при выключенной отправке провайдеру ничего не уходит"


# --- Воркер: сквозная криптография -------------------------------------------


def test_worker_delivers_double_encrypted_payload_and_test_roundtrip(push_settings):
    with TestClient(create_app(push_settings)) as client:
        pair = _pair(client)
        plaintext = b'{"type":"message","peer":1}'
        assert _ingress(client, pair, plaintext).status_code == 201

        captured: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(201)

        assert _run_worker(client, handler) == 1
        assert len(captured) == 1
        request = captured[0]
        assert request.url.host == "web.push.apple.com"
        assert request.headers["content-encoding"] == "aes128gcm"
        assert int(request.headers["ttl"]) > 0
        claims = verify_vapid_authorization(
            request.headers["authorization"],
            public_key_b64=client.app.state.context.push.vapid.public_key_b64,
            now=time.time(),
        )
        assert claims["aud"] == "https://web.push.apple.com"
        inner = pair["browser"].open_outer(request.content)
        assert pair["browser"].open_inner(inner) == plaintext
        row = client.app.state.context.push_db.connection.execute(
            "SELECT state, last_status FROM push_deliveries"
        ).fetchone()
        assert row["state"] == "done" and row["last_status"] == 201

        test = client.post(f"/api/v1/push/registrations/{pair['rid']}/test", headers=_auth(pair["token"]))
        assert test.status_code == 202
        test_id = test.json()["test_id"]
        captured.clear()
        assert _run_worker(client, handler) == 1
        decoded = json.loads(pair["browser"].open_inner(pair["browser"].open_outer(captured[0].content)))
        assert decoded["k"] == "test" and decoded["id"] == test_id
        ack = client.post(
            f"/api/v1/push/registrations/{pair['rid']}/ack", headers=_auth(pair["token"]), json={"test_id": test_id}
        )
        assert ack.json() == {"acknowledged": True}
        bogus = client.post(
            f"/api/v1/push/registrations/{pair['rid']}/ack", headers=_auth(pair["token"]), json={"test_id": "x" * 12}
        )
        assert bogus.json() == {"acknowledged": False}


def test_transient_errors_are_retried_with_retry_after(push_settings):
    with TestClient(create_app(push_settings)) as client:
        pair = _pair(client)
        _ingress(client, pair, b"retry me")
        start = time.time()
        assert _run_worker(client, lambda r: httpx.Response(503, headers={"Retry-After": "120"}), at=start) == 1
        db = client.app.state.context.push_db.connection
        row = db.execute("SELECT state, next_attempt_at, attempts, last_status FROM push_deliveries").fetchone()
        assert row["state"] == "queued" and row["attempts"] == 1 and row["last_status"] == 503
        assert start + 100 < row["next_attempt_at"] < start + 200

        assert _run_worker(client, lambda r: httpx.Response(201), at=start + 130) == 1
        assert db.execute("SELECT state FROM push_deliveries").fetchone()["state"] == "done"


def test_provider_gone_revokes_registration(push_settings):
    with TestClient(create_app(push_settings)) as client:
        pair = _pair(client)
        _ingress(client, pair, b"gone soon")
        assert _run_worker(client, lambda r: httpx.Response(410)) == 1
        view = client.get(f"/api/v1/push/registrations/{pair['rid']}", headers=_auth(pair["owner"])).json()
        assert view["state"] == "revoked"
        assert view["last_push_error"] == "provider_gone"
        assert _ingress(client, pair, b"later").status_code == 404


def test_unforwarded_payload_expires_by_ttl(push_settings):
    with TestClient(create_app(push_settings)) as client:
        pair = _pair(client)
        assert _ingress(client, pair, b"short lived", ttl="1").status_code == 201
        calls: list[httpx.Request] = []
        assert _run_worker(client, lambda r: calls.append(r) or httpx.Response(201), at=time.time() + 30) == 0
        assert calls == []
        state = client.app.state.context.push_db.connection.execute("SELECT state FROM push_deliveries").fetchone()
        assert state["state"] == "expired"


# --- Админка и страницы PWA --------------------------------------------------


def test_admin_push_page_needs_session_and_csrf_for_actions(push_settings):
    settings = push_settings.model_copy(update={"admin_token": ADMIN_TOKEN})
    with TestClient(create_app(settings)) as client:
        pair = _pair(client)
        assert client.get("/admin/push", follow_redirects=False).status_code == 303
        client.post("/admin/login", data={"token": ADMIN_TOKEN}, follow_redirects=False)
        page = client.get("/admin/push")
        assert page.status_code == 200
        assert "BG Push" in page.text and pair["rid"] not in page.text.replace(pair["rid"][:8], "")
        assert "web.push.apple.com/" not in page.text
        csrf = re.search(r"name='csrf' value='([^']+)'", page.text).group(1)

        rejected = client.post("/admin/push/revoke", data={"registration_id": pair["rid"]})
        assert "CSRF" in rejected.text
        accepted = client.post(
            "/admin/push/revoke",
            data={"csrf": csrf, "registration_id": pair["rid"]},
            follow_redirects=False,
        )
        assert accepted.status_code == 303
        view = client.get(f"/api/v1/push/registrations/{pair['rid']}", headers=_auth(pair["owner"])).json()
        assert view["state"] == "revoked"
        audit = client.app.state.context.db.connection.execute(
            "SELECT action FROM audit_log WHERE action = 'push_revoke'"
        ).fetchall()
        assert len(audit) == 1


def test_pwa_pages_headers_and_static_whitelist(push_settings):
    with TestClient(create_app(push_settings)) as client:
        index = client.get("/push/")
        assert index.status_code == 200
        assert "text/html" in index.headers["content-type"]
        assert "default-src 'none'" in index.headers["content-security-policy"]
        assert index.headers["referrer-policy"] == "no-referrer"
        assert client.get("/push/setup").status_code == 200
        assert client.get("/push/open").status_code == 200
        sw = client.get("/push/sw.js")
        assert sw.status_code == 200
        assert sw.headers["service-worker-allowed"] == "/push/"
        assert client.get("/push/manifest.webmanifest").status_code == 200
        assert client.get("/push/assets/js/bg-core.js").status_code == 200
        assert client.get("/push/assets/%2e%2e/%2e%2e/config.py").status_code == 404
        assert client.get("/push/assets/js/nothing.exe").status_code == 404
        assert client.get("/push/assets/js/missing.js").status_code == 404


def test_readyz_reports_push_without_failing_the_api(push_settings):
    with TestClient(create_app(push_settings)) as client:
        body = client.get("/readyz").json()
        assert body["status"] == "ok", "push не должен переводить весь API в degraded"
        assert body["push"]["ingress_enabled"] is True
        assert body["push"]["status"] == "degraded"  # воркер выключен в тестовой конфигурации
