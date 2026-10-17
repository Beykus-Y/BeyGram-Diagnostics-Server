"""Тесты редакции секретов — вторая линия защиты."""

from __future__ import annotations

from app.redaction import RedactionStats, redact_text, scrub_attr_value


def test_bot_token_removed():
    text = "token 123456789:AAF-abcdefghijklmnopqrstuvwxyz0123456789 leaked"
    out = redact_text(text)
    assert "AAF-" not in out
    assert "[redacted]" in out


def test_subscription_url_reduced_to_scheme():
    text = "config vless://uuid-1234@example.com:443?security=reality#node"
    out = redact_text(text)
    assert "example.com" not in out
    assert "uuid-1234" not in out
    assert out.startswith("config vless://")


def test_private_ip_removed():
    out = redact_text("connect to 192.168.1.10:1080 failed")
    assert "192.168.1.10" not in out


def test_yaml_secret_lines_removed():
    yaml = "proxies:\n  - name: node\n    uuid: 123e4567-e89b-42d3-a456-426614174000\n    password: hunter2"
    out = redact_text(yaml)
    assert "hunter2" not in out
    assert "123e4567-e89b-42d3-a456-426614174000" not in out


def test_phone_and_email_removed():
    out = redact_text("call +7 999 123-45-67 or write to user@example.com")
    assert "+7 999 123-45-67" not in out
    assert "user@example.com" not in out


def test_telegram_links_removed():
    out = redact_text("see https://t.me/some_channel/123")
    assert "some_channel" not in out


def test_sensitive_attribute_key_drops_value():
    stats = RedactionStats()
    out = scrub_attr_value("password", "supersecret", stats)
    assert out == "[redacted]"
    assert stats.counts.get("sensitive_attr") == 1


def test_benign_metrics_survive():
    """Обычные диагностические метрики не должны вырезаться."""
    stats = RedactionStats()
    out = scrub_attr_value("latency_ms", "342", stats)
    assert out == "342"

    out2 = redact_text("connection timeout after 30s, retries=3")
    assert "timeout" in out2
    assert "retries=3" in out2


def test_allowed_host_is_kept():
    out = redact_text("https://core.telegram.org/method/messages.sendMessage failed")
    assert "core.telegram.org" in out


def test_stats_accumulate():
    stats = RedactionStats()
    redact_text("token=abcdef1234567890 password=xyzsecret", stats)
    assert stats.total >= 1
