"""Тесты криптографии: формат nonce, хэширование, status-токен."""

from __future__ import annotations

import pytest

from app.security import (
    NonceFormatError,
    generate_nonce,
    hash_ip,
    hash_nonce,
    make_status_token,
    validate_nonce,
    verify_status_token,
)


def test_generated_nonce_is_256_bits_base64url():
    nonce = generate_nonce()
    assert len(nonce) == 43
    assert "=" not in nonce
    validated = validate_nonce(nonce)
    assert len(validated.raw_bytes) == 32


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "short",
        "a" * 42,
        "a" * 44,
        "a" * 43 + "=",
        "!" * 43,
        "A" * 42 + "=",
    ],
)
def test_invalid_nonce_rejected(bad):
    with pytest.raises(NonceFormatError):
        validate_nonce(bad)


def test_nonce_hash_is_keyed_and_not_reversible():
    nonce = generate_nonce()
    pepper_a = "pepper-a-0123456789-0123456789-0123456789"
    pepper_b = "pepper-b-0123456789-0123456789-0123456789"

    h_a = hash_nonce(pepper_a, nonce)
    h_b = hash_nonce(pepper_b, nonce)

    assert h_a != h_b, "разные pepper должны давать разные хэши"
    assert nonce not in h_a
    assert len(h_a) == 64


def test_nonce_hash_is_deterministic():
    nonce = generate_nonce()
    pepper = "p" * 40
    assert hash_nonce(pepper, nonce) == hash_nonce(pepper, nonce)


def test_status_token_verification():
    pepper = "p" * 40
    report_id = "123e4567-e89b-42d3-a456-426614174000"
    token = make_status_token(pepper, report_id, 42)

    assert verify_status_token(pepper, token, report_id, 42)
    assert not verify_status_token(pepper, token, report_id, 43)
    assert not verify_status_token(pepper, token, "123e4567-e89b-42d3-a456-426614174001", 42)
    assert not verify_status_token("x" * 40, token, report_id, 42)


def test_ip_hash_hides_raw_ip():
    pepper = "p" * 40
    hashed = hash_ip(pepper, "203.0.113.7")
    assert "203.0.113.7" not in hashed
    assert hash_ip(pepper, "203.0.113.7") == hashed
    assert hash_ip(pepper, None) != hashed
