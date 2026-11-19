"""BG Push: криптография (RFC 8188/8291/8292), хранилище, проверка endpoint-ов, ключи и конфигурация."""

from __future__ import annotations

import os
import stat

import http_ece
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import ValidationError

from app.config import Settings
from app.middleware import _loggable_path
from app.push import crypto
from app.push.crypto import (
    PushCryptoError,
    VapidKey,
    decrypt_aes128gcm,
    encrypt_aes128gcm,
    generate_vapid_pem,
    vapid_authorization,
    verify_vapid_authorization,
)
from app.push.keygen import main as keygen_main
from app.push.urls import DEFAULT_ALLOWED_HOSTS, EndpointError, parse_allowed_hosts, validate_endpoint
from app.push.vault import Vault, VaultError
from app.util import b64url_encode

ALLOWED = ("web.push.apple.com", "push.services.mozilla.com", "fcm.googleapis.com")


def _receiver() -> tuple[ec.EllipticCurvePrivateKey, bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    return key, crypto.public_key_bytes(key.public_key()), os.urandom(16)


# --- aes128gcm (RFC 8188 / RFC 8291) ----------------------------------------


def test_aes128gcm_roundtrip_and_header_layout():
    key, pub, auth = _receiver()
    body = encrypt_aes128gcm(b"hello push", ua_public=pub, auth_secret=auth)
    assert body[16:20] == (4096).to_bytes(4, "big")
    assert body[20] == 65
    assert body[21:86] != pub  # ключ отправителя эфемерный, не ключ получателя
    assert decrypt_aes128gcm(body, private_key=key, auth_secret=auth) == b"hello push"


def test_aes128gcm_rejects_wrong_secret_and_tampering():
    key, pub, auth = _receiver()
    body = encrypt_aes128gcm(b"payload", ua_public=pub, auth_secret=auth)
    with pytest.raises(PushCryptoError):
        decrypt_aes128gcm(body, private_key=key, auth_secret=os.urandom(16))
    tampered = body[:-1] + bytes([body[-1] ^ 1])
    with pytest.raises(PushCryptoError):
        decrypt_aes128gcm(tampered, private_key=key, auth_secret=auth)


def test_single_record_plaintext_limit():
    _, pub, auth = _receiver()
    encrypt_aes128gcm(b"x" * crypto.MAX_PLAINTEXT, ua_public=pub, auth_secret=auth)
    with pytest.raises(PushCryptoError):
        encrypt_aes128gcm(b"x" * (crypto.MAX_PLAINTEXT + 1), ua_public=pub, auth_secret=auth)


def test_rejects_invalid_receiver_keys():
    _, _, auth = _receiver()
    with pytest.raises(PushCryptoError):
        encrypt_aes128gcm(b"x", ua_public=b"\x04" + b"\x00" * 64, auth_secret=auth)  # точка не на кривой
    with pytest.raises(PushCryptoError):
        encrypt_aes128gcm(b"x", ua_public=b"\x02" + b"\x00" * 64, auth_secret=auth)  # сжатая форма
    with pytest.raises(PushCryptoError):
        encrypt_aes128gcm(b"x", ua_public=_receiver()[1], auth_secret=b"short")


def test_interoperates_with_reference_implementation_http_ece():
    key, pub, auth = _receiver()
    ours = encrypt_aes128gcm(b"interop-1", ua_public=pub, auth_secret=auth)
    assert http_ece.decrypt(ours, private_key=key, auth_secret=auth) == b"interop-1"

    sender = ec.generate_private_key(ec.SECP256R1())
    reference = http_ece.encrypt(b"interop-2", private_key=sender, dh=pub, auth_secret=auth)
    assert decrypt_aes128gcm(reference, private_key=key, auth_secret=auth) == b"interop-2"


# --- VAPID (RFC 8292) -------------------------------------------------------


def test_vapid_header_verifies_and_binds_audience():
    vapid = VapidKey.from_pem(generate_vapid_pem())
    now = 1_700_000_000.0
    header = vapid_authorization(
        vapid, audience="https://web.push.apple.com", subject="mailto:push@example.com", now=now
    )
    assert header.startswith("vapid t=") and f", k={vapid.public_key_b64}" in header
    claims = verify_vapid_authorization(header, public_key_b64=vapid.public_key_b64, now=now)
    assert claims["aud"] == "https://web.push.apple.com"
    assert claims["sub"] == "mailto:push@example.com"
    assert claims["exp"] - int(now) == 12 * 3600


def test_vapid_rejects_foreign_key_tampering_and_expiry():
    vapid = VapidKey.from_pem(generate_vapid_pem())
    other = VapidKey.from_pem(generate_vapid_pem())
    now = 1_700_000_000.0
    header = vapid_authorization(vapid, audience="https://fcm.googleapis.com", subject="mailto:a@b.example", now=now)
    with pytest.raises(PushCryptoError):
        verify_vapid_authorization(header, public_key_b64=other.public_key_b64, now=now)
    head, _ = header.split(", k=")
    parts = head[len("vapid t=") :].split(".")
    forged = f"vapid t={parts[0]}.{parts[1]}.{b64url_encode(b'\x00' * 64)}, k={vapid.public_key_b64}"
    with pytest.raises(PushCryptoError):
        verify_vapid_authorization(forged, public_key_b64=vapid.public_key_b64, now=now)
    with pytest.raises(PushCryptoError):
        verify_vapid_authorization(header, public_key_b64=vapid.public_key_b64, now=now + 13 * 3600)


def test_vapid_key_must_be_p256_pem():
    with pytest.raises(PushCryptoError):
        VapidKey.from_pem(b"not a key")
    rsa_like = b"-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"
    with pytest.raises(PushCryptoError):
        VapidKey.from_pem(rsa_like)


# --- Endpoint-ы: SSRF и белый список ----------------------------------------


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://web.push.apple.com/abc123",
        "https://web.push.apple.com:443/abc123",
        "https://updates.push.services.mozilla.com/wpush/v2/xyz",
        "https://fcm.googleapis.com/fcm/send/abc",
    ],
)
def test_accepts_known_push_providers(endpoint):
    host = validate_endpoint(endpoint, ALLOWED)
    assert any(host == allowed or host.endswith("." + allowed) for allowed in ALLOWED)


@pytest.mark.parametrize(
    "endpoint",
    [
        "",
        "http://web.push.apple.com/abc",
        "https://user:secret@web.push.apple.com/abc",
        "https://web.push.apple.com:8443/abc",
        "https://web.push.apple.com/abc#fragment",
        "https://93.184.216.34/abc",
        "https://169.254.169.254/latest/meta-data",
        "https://[2001:db8::1]/abc",
        "https://localhost/abc",
        "https://example.com/abc",
        "https://web.push.apple.com.evil.example/abc",
        "https://evilweb.push.apple.com/abc",
        "https://web.push.apple.com/abc def",
        "https:///path",
        "https://web.push.apple.com/" + "a" * 2100,
    ],
)
def test_rejects_unsafe_endpoints(endpoint):
    with pytest.raises(EndpointError):
        validate_endpoint(endpoint, ALLOWED)


def test_allowed_hosts_configuration():
    assert parse_allowed_hosts("") == DEFAULT_ALLOWED_HOSTS
    assert parse_allowed_hosts("A.Example.com., b.example.org") == ("a.example.com", "b.example.org")
    with pytest.raises(ValueError):
        parse_allowed_hosts("bad host")


# --- Хранилище at rest -------------------------------------------------------


def test_vault_seal_open_binds_context_and_digests_are_labelled():
    vault = Vault(os.urandom(32))
    sealed = vault.seal("https://web.push.apple.com/abc", aad="rid:endpoint")
    assert "web.push.apple.com" not in sealed
    assert vault.open(sealed, aad="rid:endpoint") == "https://web.push.apple.com/abc"
    with pytest.raises(VaultError):
        vault.open(sealed, aad="other:endpoint")
    with pytest.raises(VaultError):
        Vault(os.urandom(32)).open(sealed, aad="rid:endpoint")
    assert vault.digest("owner", "x") != vault.digest("token", "x")
    assert vault.digest("owner", "x") == vault.digest("owner", "x")


def test_vault_key_file_format(tmp_path):
    path = tmp_path / "storage.key"
    path.write_text(b64url_encode(os.urandom(16)) + "\n")
    with pytest.raises(VaultError):
        Vault.from_file(path)
    path.write_text(b64url_encode(os.urandom(32)) + "\n")
    Vault.from_file(path)
    with pytest.raises(VaultError):
        Vault.from_file(tmp_path / "missing.key")


def test_keygen_writes_private_files_once(tmp_path, capsys):
    assert keygen_main([str(tmp_path)]) == 0
    pem = tmp_path / "vapid_private.pem"
    storage = tmp_path / "storage.key"
    assert stat.S_IMODE(pem.stat().st_mode) == 0o600
    assert stat.S_IMODE(storage.stat().st_mode) == 0o600
    before = pem.read_bytes()
    assert keygen_main([str(tmp_path)]) == 0
    assert pem.read_bytes() == before
    out = capsys.readouterr().out
    assert "applicationServerKey" in out
    # В выводе есть пути и публичный ключ, но не содержимое закрытых ключей.
    pem_lines = pem.read_text().splitlines()
    assert "BEGIN PRIVATE KEY" not in out
    assert pem_lines[1] not in out
    secret = storage.read_bytes().strip()
    assert secret and secret not in out.encode("utf-8")


# --- Конфигурация и логи -----------------------------------------------------


def _push_settings(**overrides) -> dict:
    base = {
        "app_env": "test",
        "nonce_pepper": "x" * 40,
        "enable_push": True,
        "push_public_base_url": "https://push.example",
        "push_vapid_private_key_file": "/keys/vapid.pem",
        "push_storage_key_file": "/keys/storage.key",
        "push_vapid_subject": "mailto:push@example.com",
    }
    base.update(overrides)
    return base


def test_push_configuration_is_validated_when_enabled():
    Settings(**_push_settings())
    with pytest.raises(ValidationError):
        Settings(**_push_settings(push_public_base_url="http://push.example"))
    with pytest.raises(ValidationError):
        Settings(**_push_settings(push_storage_key_file=""))
    with pytest.raises(ValidationError):
        Settings(**_push_settings(push_vapid_subject="push@example.com"))
    with pytest.raises(ValidationError):
        Settings(**_push_settings(push_allowed_endpoint_hosts="bad host"))
    with pytest.raises(ValidationError):
        Settings(**_push_settings(push_pairing_ttl_seconds=5))
    disabled = Settings(**_push_settings(enable_push=False, push_public_base_url="http://x"))
    assert disabled.enable_push is False


def test_ingress_capability_is_redacted_in_logs():
    capability = "A" * 43
    assert _loggable_path(f"/api/v1/push/ingress/{capability}") == "/api/v1/push/ingress/:capability"
    assert _loggable_path("/api/v1/analytics/sync") == "/api/v1/analytics/sync"
