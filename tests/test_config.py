"""Тесты конфигурации: валидация, allowlist, production-требования."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings


def _base(**overrides) -> dict:
    data = {
        "app_env": "test",
        "nonce_pepper": "p" * 40,
        "database_path": ":memory:",
    }
    data.update(overrides)
    return data


def test_defaults_are_safe():
    settings = Settings(**_base())
    assert settings.require_https is True
    assert settings.max_body_bytes == 262144
    assert settings.max_description_chars == 2000
    assert settings.nonce_ttl_seconds == 420
    assert 60 <= settings.nonce_ttl_seconds <= 900


def test_bootstrap_allowlist_parsing():
    settings = Settings(**_base(bootstrap_allowlist="111, 222;333, bad, -5"))
    assert settings.bootstrap_allowlist_ids == {111, 222, 333}


def test_short_pepper_rejected():
    with pytest.raises(ValidationError):
        Settings(**_base(nonce_pepper="short"))


def test_ttl_bounds_enforced():
    with pytest.raises(ValidationError):
        Settings(**_base(nonce_ttl_seconds=10))
    with pytest.raises(ValidationError):
        Settings(**_base(nonce_ttl_seconds=3600))


def test_body_limit_bounds_enforced():
    with pytest.raises(ValidationError):
        Settings(**_base(max_body_bytes=1024))
    with pytest.raises(ValidationError):
        Settings(**_base(max_body_bytes=10 * 1024 * 1024))


def test_production_requires_bot_token():
    with pytest.raises(ValidationError):
        Settings(**_base(app_env="production", report_bot_token="", delivery_chat_id=0))


def test_delivery_token_defaults_to_report_token():
    settings = Settings(**_base(report_bot_token="123:ABC"))
    assert settings.delivery_bot_token == "123:ABC"


def test_https_base_required():
    with pytest.raises(ValidationError):
        Settings(**_base(telegram_api_base="ftp://example.com"))


def test_trusted_proxy_networks_include_private_ranges():
    settings = Settings(**_base())
    networks = settings.trusted_proxy_networks
    assert any(str(net) == "127.0.0.0/8" for net in networks)
    assert any(str(net) == "10.0.0.0/8" for net in networks)


def test_extra_trusted_proxy_network_parsed():
    settings = Settings(**_base(trusted_proxy_networks_raw="100.64.0.0/10, invalid"))
    networks = [str(net) for net in settings.trusted_proxy_networks]
    assert "100.64.0.0/10" in networks
