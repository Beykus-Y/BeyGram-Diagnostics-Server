"""Тесты middleware: санитизация внешнего X-Request-ID (#16)."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

_SAFE_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")


@pytest.fixture()
def client(settings):
    app = create_app(settings)
    with TestClient(app) as c:
        yield c


def test_safe_request_id_passes_through(client):
    response = client.get("/healthz", headers={"X-Request-ID": "run-2026.10_17-ab"})
    assert response.headers["X-Request-ID"] == "run-2026.10_17-ab"


def test_request_id_with_newline_replaced(client):
    malicious = "evil\nAuthorization: Bearer sekret"
    response = client.get("/healthz", headers={"X-Request-ID": malicious})
    got = response.headers["X-Request-ID"]
    assert got != malicious
    assert _SAFE_RE.match(got), "заменённый id должен быть в безопасном формате"


def test_request_id_with_special_chars_replaced(client):
    for malicious in ('"onerror=alert(1)', "a b", "<script>", "x" * 100, "id;drop", "a:b:c"):
        response = client.get("/healthz", headers={"X-Request-ID": malicious})
        got = response.headers["X-Request-ID"]
        assert got != malicious
        assert _SAFE_RE.match(got)


def test_empty_request_id_generates_one(client):
    response = client.get("/healthz", headers={"X-Request-ID": ""})
    assert _SAFE_RE.match(response.headers["X-Request-ID"])


def test_generated_request_id_is_safe(client):
    response = client.get("/healthz")
    assert _SAFE_RE.match(response.headers["X-Request-ID"])
