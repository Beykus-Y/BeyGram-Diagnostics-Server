"""Ресурсы BG Push, которые читаются при старте: ключи, хосты, публичный адрес."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..config import API_PREFIX, Settings
from .crypto import VapidKey
from .urls import parse_allowed_hosts
from .vault import Vault


@dataclass(frozen=True)
class PushRuntime:
    vault: Vault
    vapid: VapidKey
    subject: str
    public_base_url: str
    allowed_hosts: tuple[str, ...]

    @classmethod
    def load(cls, settings: Settings) -> PushRuntime:
        """Читает ключи с диска. Ошибка здесь останавливает запуск (fail fast)."""
        vault = Vault.from_file(settings.push_storage_key_file)
        vapid = VapidKey.from_pem(Path(settings.push_vapid_private_key_file).read_bytes())
        return cls(
            vault=vault,
            vapid=vapid,
            subject=settings.push_vapid_subject,
            public_base_url=settings.push_public_base_url.rstrip("/"),
            allowed_hosts=parse_allowed_hosts(settings.push_allowed_endpoint_hosts),
        )

    def ingress_url(self, capability: str) -> str:
        return f"{self.public_base_url}{API_PREFIX}/push/ingress/{capability}"
