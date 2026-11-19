"""Генерация ключей BG Push.

Использование (один раз, на сервере, в каталоге вне git):

    python -m app.push.keygen /data/push

Создаёт vapid_private.pem (P-256, PKCS#8) и storage.key (32 случайных байта в
base64url). Файлы создаются с правами 0600 и не перезаписываются. Выводятся
только публичный ключ VAPID и пути; секреты в stdout не печатаются.
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

from ..util import b64url_encode
from .crypto import VapidKey, generate_vapid_pem


def _write_private(path: Path, data: bytes) -> bool:
    """Создаёт файл только если его нет; возвращает True при создании."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return True


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python -m app.push.keygen <directory>", file=sys.stderr)
        return 2
    directory = Path(args[0])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    vapid_path = directory / "vapid_private.pem"
    storage_path = directory / "storage.key"
    created_vapid = _write_private(vapid_path, generate_vapid_pem())
    created_storage = _write_private(storage_path, (b64url_encode(secrets.token_bytes(32)) + "\n").encode("ascii"))
    key = VapidKey.from_pem(vapid_path.read_bytes())
    print(f"vapid private key: {vapid_path} ({'created' if created_vapid else 'existing'})")
    print(f"storage key:       {storage_path} ({'created' if created_storage else 'existing'})")
    print(f"VAPID public key (applicationServerKey): {key.public_key_b64}")
    print("Добавьте в .env: ENABLE_PUSH=true, PUSH_VAPID_PRIVATE_KEY_FILE, PUSH_STORAGE_KEY_FILE, PUSH_VAPID_SUBJECT.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
