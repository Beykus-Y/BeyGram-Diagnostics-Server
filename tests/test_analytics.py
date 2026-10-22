"""Installation analytics: no bot handshake, no Telegram IDs stored."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from app.main import create_app
from app.repository import allowlist
from app.security import generate_nonce


def request_payload(**overrides):
    payload = {
        "installation_id": str(uuid.uuid4()),
        "revision": 1,
        "app_version": "0.0.2.0",
        "app_version_code": 20,
        "release_channel": "stable",
        "android_version": "16",
        "device_model": "Samsung M21",
        "account_count": 0,
    }
    payload.update(overrides)
    return payload


def send(client, payload, token):
    return client.post(
        "/api/v1/analytics/sync",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )


def test_register_without_account_or_bot(settings):
    with TestClient(create_app(settings)) as client:
        token, payload = generate_nonce(), request_payload()
        first = send(client, payload, token)
        assert first.status_code == 200, first.text
        assert first.json() == {
            "registered": True, "updated": True
        }
        replay = send(client, payload, token)
        assert replay.status_code == 200
        assert replay.json()["registered"] is False
        assert replay.json()["updated"] is False
        db = client.app.state.context.db
        assert db.query_one("SELECT COUNT(*) FROM analytics_installations")[0] == 1
        assert db.query_one("SELECT COUNT(*) FROM analytics_versions")[0] == 1
        assert db.query_one("SELECT COUNT(*) FROM analytics_activity_days")[0] == 1


def test_version_upgrade_downgrade_and_replay(settings):
    with TestClient(create_app(settings)) as client:
        token, payload = generate_nonce(), request_payload()
        assert send(client, payload, token).status_code == 200
        changed = {**payload, "revision": 2, "app_version": "0.0.2.1",
                   "app_version_code": 21, "account_count": 2}
        assert send(client, changed, token).json()["updated"]
        db = client.app.state.context.db
        assert db.query_one("SELECT app_version FROM analytics_installations")[0] == "0.0.2.1"
        assert db.query_one("SELECT COUNT(*) FROM analytics_versions")[0] == 2
        assert send(client, changed, token).json()["updated"] is False
        assert send(client, payload, token).json()["updated"] is False
        assert db.query_one("SELECT app_version FROM analytics_installations")[0] == "0.0.2.1"
        assert db.query_one("SELECT COUNT(*) FROM analytics_versions")[0] == 2
        downgrade = {**payload, "revision": 3}
        assert send(client, downgrade, token).json()["updated"]
        assert db.query_one("SELECT COUNT(*) FROM analytics_versions")[0] == 3


def test_allowlist_beta_status_without_persisting_ids(settings):
    with TestClient(create_app(settings)) as client:
        token, payload = generate_nonce(), request_payload(account_count=2)
        db = client.app.state.context.db
        with db.transaction() as conn:
            allowlist.add(conn, 87654321)
        payload["telegram_user_ids"] = [12345678, 87654321]
        assert send(client, payload, token).status_code == 200
        assert db.query_one("SELECT beta_status FROM analytics_installations")[0] == "approved"
        with db.transaction() as conn:
            allowlist.revoke(conn, 87654321)
        payload["revision"] = 2
        assert send(client, payload, token).status_code == 200
        assert db.query_one("SELECT beta_status FROM analytics_installations")[0] == "not_approved"
        payload["revision"] = 3
        payload["telegram_user_ids"] = [12345678]
        assert send(client, payload, token).status_code == 200
        assert db.query_one("SELECT beta_status FROM analytics_installations")[0] == "unknown"
        # TG identifiers are absent even as strings in analytics tables.
        for table in ("analytics_installations", "analytics_activity_days", "analytics_versions"):
            rows = db.query_all(f"SELECT * FROM {table}")
            assert "87654321" not in str([dict(r) for r in rows])
            assert "12345678" not in str([dict(r) for r in rows])


def test_installation_token_protects_update_and_deletion(settings):
    with TestClient(create_app(settings)) as client:
        token, payload = generate_nonce(), request_payload()
        assert send(client, payload, token).status_code == 200
        hijack = {**payload, "revision": 2, "app_version": "evil"}
        assert send(client, hijack, generate_nonce()).status_code == 401
        assert client.delete(
            f"/api/v1/analytics/installations/{payload['installation_id']}",
            headers={"Authorization": f"Bearer {generate_nonce()}"},
        ).status_code == 401
        assert client.app.state.context.db.query_one(
            "SELECT app_version FROM analytics_installations"
        )[0] == "0.0.2.0"
        assert client.delete(
            f"/api/v1/analytics/installations/{payload['installation_id']}",
            headers={"Authorization": f"Bearer {token}"},
        ).json() == {"deleted": True}
        assert client.app.state.context.db.query_one(
            "SELECT COUNT(*) FROM analytics_installations"
        )[0] == 0
        assert client.app.state.context.db.query_one(
            "SELECT COUNT(*) FROM analytics_versions"
        )[0] == 0


def test_reject_invalid_payload_and_extra_data(settings):
    with TestClient(create_app(settings)) as client:
        token = generate_nonce()
        assert send(client, request_payload(telegram_user_id=111), token).status_code == 422
        assert send(client, request_payload(account_count=-1), token).status_code == 422
        assert send(client, request_payload(telegram_user_ids=[111] * 21), token).status_code == 422
        assert send(client, request_payload(installation_id="invalid"), token).status_code == 422
        assert send(client, request_payload(), "short").status_code == 401


def test_no_account_is_unknown_even_with_active_allowlist(settings):
    with TestClient(create_app(settings)) as client:
        with client.app.state.context.db.transaction() as conn:
            allowlist.add(conn, 87654321)
        token, payload = generate_nonce(), request_payload()
        assert send(client, payload, token).status_code == 200
        assert client.app.state.context.db.query_one("SELECT beta_status FROM analytics_installations")[0] == "unknown"


def test_registration_rate_limit_does_not_block_existing(settings):
    settings.rl_analytics_registrations_per_day = 1
    with TestClient(create_app(settings)) as client:
        token, payload = generate_nonce(), request_payload()
        assert send(client, payload, token).status_code == 200
        assert send(client, request_payload(), generate_nonce()).status_code == 429
        payload["revision"] = 2
        assert send(client, payload, token).status_code == 200


def test_analytics_disabled_but_delete_still_works(settings):
    with TestClient(create_app(settings)) as client:
        token, payload = generate_nonce(), request_payload()
        assert send(client, payload, token).status_code == 200
        settings.accept_analytics = False
        assert send(client, payload, token).status_code == 503
        resp = client.delete(
            f"/api/v1/analytics/installations/{payload['installation_id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200


def test_admin_dashboard_private_filters_and_no_ids(settings):
    settings.admin_token = "test-admin-token-0123456789"
    with TestClient(create_app(settings)) as client:
        assert client.get("/admin/analytics", follow_redirects=False).status_code == 303
        assert client.post("/admin/login", data={"token": settings.admin_token},
                           follow_redirects=False).status_code == 303
        token, payload = generate_nonce(), request_payload(
            account_count=1, telegram_user_ids=[912345678]
        )
        with client.app.state.context.db.transaction() as conn:
            allowlist.add(conn, 912345678)
        assert send(client, payload, token).status_code == 200
        resp = client.get("/admin/analytics?status=approved&channel=stable")
        assert resp.status_code == 200
        assert "Аналитика BeyGram" in resp.text
        assert "0.0.2.0" in resp.text
        assert "912345678" not in resp.text
        assert client.get("/admin/analytics?status=not_approved").text.count(
            "Установки не найдены"
        ) == 1


def test_analytics_prune_removes_old_installations(settings):
    from app.repository.analytics import prune

    with TestClient(create_app(settings)) as client:
        token, payload = generate_nonce(), request_payload()
        assert send(client, payload, token).status_code == 200
        db = client.app.state.context.db
        with db.transaction() as conn:
            conn.execute("UPDATE analytics_installations SET last_seen_at=1")
            assert prune(conn, at=100 * 86400, retention_days=90) == 1
            assert conn.execute("SELECT COUNT(*) FROM analytics_versions").fetchone()[0] == 0
            assert conn.execute("SELECT COUNT(*) FROM analytics_activity_days").fetchone()[0] == 0


def test_no_analytics_registration_token_leaks_into_reports(settings):
    with TestClient(create_app(settings)) as client:
        token, payload = generate_nonce(), request_payload()
        assert send(client, payload, token).status_code == 200
        assert client.app.state.context.db.query_one(
            "SELECT COUNT(*) FROM reports"
        )[0] == 0
        assert client.app.state.context.db.query_one(
            "SELECT COUNT(*) FROM nonces"
        )[0] == 0


def test_credentials_survive_report_pepper_rotation(settings):
    with TestClient(create_app(settings)) as client:
        token, payload = generate_nonce(), request_payload()
        assert send(client, payload, token).status_code == 200
        settings.nonce_pepper = "rotated-pepper-at-least-thirty-two-chars"
        payload["revision"] = 2
        assert send(client, payload, token).status_code == 200
        deleted = client.delete(
            f"/api/v1/analytics/installations/{payload['installation_id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert deleted.status_code == 200


def test_uppercase_deletion_and_case_insensitive_bearer(settings):
    with TestClient(create_app(settings)) as client:
        token, payload = generate_nonce(), request_payload()
        response = client.post(
            "/api/v1/analytics/sync", json=payload,
            headers={"Authorization": f"bearer {token}"},
        )
        assert response.status_code == 200
        deleted = client.delete(
            f"/api/v1/analytics/installations/{payload['installation_id'].upper()}",
            headers={"Authorization": f"BEARER {token}"},
        )
        assert deleted.status_code == 200


def test_android_model_accepts_unicode_and_parentheses(settings):
    with TestClient(create_app(settings)) as client:
        token, payload = generate_nonce(), request_payload(device_model="moto g(7) power")
        assert send(client, payload, token).status_code == 200
        payload["revision"] = 2
        payload["device_model"] = "Модель (特殊) 5G"
        assert send(client, payload, token).status_code == 200
        payload["revision"] = 3
        payload["device_model"] = "model\\nspoof"
        assert send(client, payload, token).status_code == 422


def test_v3_migration_recovers_from_stale_schema_version(tmp_db_path):
    from app.db import Database, SCHEMA_VERSION

    original = Database(tmp_db_path)
    original.connect()
    assert SCHEMA_VERSION == 3
    original.connection.execute("UPDATE schema_version SET version=2")
    original.close()
    recovered = Database(tmp_db_path)
    try:
        recovered.connect()
        assert recovered.connection.execute("SELECT version FROM schema_version").fetchone()[0] == 3
        assert recovered.connection.execute(
            "SELECT COUNT(*) FROM analytics_installations"
        ).fetchone()[0] == 0
    finally:
        recovered.close()
