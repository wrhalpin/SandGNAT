"""Environment-backed configuration.

All runtime knobs live here. Never hard-code hosts, tokens, or paths elsewhere.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


def _env(name: str, default: str | None = None, *, required: bool = False) -> str:
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"Required environment variable {name!r} is not set")
    return value or ""


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class ProxmoxConfig:
    host: str
    user: str
    token_name: str
    token_value: str
    verify_ssl: bool
    node: str
    template_vmid: int
    clean_snapshot: str


@dataclass(frozen=True)
class Settings:
    database_url: str
    broker_url: str
    result_backend: str

    proxmox: ProxmoxConfig

    analysis_network_cidr: str
    quarantine_root: str
    artifact_staging_root: str

    default_timeout_seconds: int
    max_concurrent_analyses: int


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    proxmox = ProxmoxConfig(
        host=_env("PROXMOX_HOST", required=True),
        user=_env("PROXMOX_USER", "root@pam"),
        token_name=_env("PROXMOX_TOKEN_NAME", required=True),
        token_value=_env("PROXMOX_TOKEN_VALUE", required=True),
        verify_ssl=_env_bool("PROXMOX_VERIFY_SSL", True),
        node=_env("PROXMOX_NODE", required=True),
        template_vmid=_env_int("PROXMOX_TEMPLATE_VMID", 9000),
        clean_snapshot=_env("PROXMOX_CLEAN_SNAPSHOT", "clean"),
    )
    return Settings(
        database_url=_env("DATABASE_URL", required=True),
        broker_url=_env("CELERY_BROKER_URL", "redis://localhost:6379/0"),
        result_backend=_env("CELERY_RESULT_BACKEND", "redis://localhost:6379/1"),
        proxmox=proxmox,
        analysis_network_cidr=_env("ANALYSIS_NETWORK_CIDR", "192.168.100.0/24"),
        quarantine_root=_env("QUARANTINE_ROOT", "/srv/sandgnat/quarantine"),
        artifact_staging_root=_env("ARTIFACT_STAGING_ROOT", "/srv/sandgnat/staging"),
        default_timeout_seconds=_env_int("ANALYSIS_DEFAULT_TIMEOUT", 300),
        max_concurrent_analyses=_env_int("MAX_CONCURRENT_ANALYSES", 4),
    )
