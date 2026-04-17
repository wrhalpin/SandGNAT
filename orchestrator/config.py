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


def _env_path(name: str, default: str | None = None) -> str:
    raw = os.environ.get(name, default)
    return raw or ""


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
class VmPoolConfig:
    vmid_min: int
    vmid_max: int
    stale_lease_seconds: int


@dataclass(frozen=True)
class LinuxVmPoolConfig:
    vmid_min: int
    vmid_max: int
    template_vmid: int
    clean_snapshot: str
    stale_lease_seconds: int


@dataclass(frozen=True)
class StaticAnalysisConfig:
    """Knobs for the pre-detonation Linux static-analysis stage."""

    enabled: bool
    short_circuit_threshold: float       # Jaccard estimate above which we skip detonation
    short_circuit_flavour: str           # 'byte' | 'opcode' | 'either'
    timeout_seconds: int
    yara_deep_rules_dir: str


@dataclass(frozen=True)
class IntakeConfig:
    max_sample_bytes: int
    min_sample_bytes: int
    api_key: str
    bind_host: str
    bind_port: int
    yara_rules_dir: str
    vt_api_key: str
    vt_base_url: str
    vt_timeout_seconds: float


@dataclass(frozen=True)
class Settings:
    database_url: str
    broker_url: str
    result_backend: str

    proxmox: ProxmoxConfig
    vm_pool: VmPoolConfig
    linux_vm_pool: LinuxVmPoolConfig
    static: StaticAnalysisConfig
    intake: IntakeConfig

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
    vm_pool = VmPoolConfig(
        vmid_min=_env_int("VM_POOL_VMID_MIN", 9100),
        vmid_max=_env_int("VM_POOL_VMID_MAX", 9199),
        stale_lease_seconds=_env_int("VM_POOL_STALE_LEASE_SECONDS", 1800),
    )
    linux_vm_pool = LinuxVmPoolConfig(
        vmid_min=_env_int("LINUX_VM_POOL_VMID_MIN", 9200),
        vmid_max=_env_int("LINUX_VM_POOL_VMID_MAX", 9299),
        template_vmid=_env_int("LINUX_TEMPLATE_VMID", 9001),
        clean_snapshot=_env("LINUX_CLEAN_SNAPSHOT", "clean"),
        stale_lease_seconds=_env_int("LINUX_VM_POOL_STALE_LEASE_SECONDS", 600),
    )
    static = StaticAnalysisConfig(
        enabled=_env_bool("STATIC_ANALYSIS_ENABLED", False),
        short_circuit_threshold=float(
            _env("STATIC_SHORT_CIRCUIT_THRESHOLD", "0.85")
        ),
        short_circuit_flavour=_env("STATIC_SHORT_CIRCUIT_FLAVOUR", "either"),
        timeout_seconds=_env_int("STATIC_ANALYSIS_TIMEOUT", 240),
        yara_deep_rules_dir=_env_path("STATIC_YARA_DEEP_RULES_DIR", ""),
    )
    intake = IntakeConfig(
        max_sample_bytes=_env_int("INTAKE_MAX_SAMPLE_BYTES", 128 * 1024 * 1024),
        min_sample_bytes=_env_int("INTAKE_MIN_SAMPLE_BYTES", 16),
        api_key=_env("INTAKE_API_KEY", ""),
        bind_host=_env("INTAKE_BIND_HOST", "127.0.0.1"),
        bind_port=_env_int("INTAKE_BIND_PORT", 8080),
        yara_rules_dir=_env_path("INTAKE_YARA_RULES_DIR", ""),
        vt_api_key=_env("VIRUSTOTAL_API_KEY", ""),
        vt_base_url=_env("VIRUSTOTAL_BASE_URL", "https://www.virustotal.com/api/v3"),
        vt_timeout_seconds=float(_env("VIRUSTOTAL_TIMEOUT_SECONDS", "10")),
    )
    return Settings(
        database_url=_env("DATABASE_URL", required=True),
        broker_url=_env("CELERY_BROKER_URL", "redis://localhost:6379/0"),
        result_backend=_env("CELERY_RESULT_BACKEND", "redis://localhost:6379/1"),
        proxmox=proxmox,
        vm_pool=vm_pool,
        linux_vm_pool=linux_vm_pool,
        static=static,
        intake=intake,
        analysis_network_cidr=_env("ANALYSIS_NETWORK_CIDR", "192.168.100.0/24"),
        quarantine_root=_env("QUARANTINE_ROOT", "/srv/sandgnat/quarantine"),
        artifact_staging_root=_env("ARTIFACT_STAGING_ROOT", "/srv/sandgnat/staging"),
        default_timeout_seconds=_env_int("ANALYSIS_DEFAULT_TIMEOUT", 300),
        max_concurrent_analyses=_env_int("MAX_CONCURRENT_ANALYSES", 4),
    )
