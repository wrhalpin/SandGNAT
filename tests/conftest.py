# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Test-suite-wide fixtures and environment.

`orchestrator.celery_app._make_app()` calls `get_settings()` at module-load
time so the Celery `app` constant exists for `@shared_task` decorators.
That settings call requires `DATABASE_URL`, `PROXMOX_HOST`, etc. — in the
test suite we don't actually connect to either, but we do need the import
to succeed. Stub the env to dummy values before any orchestrator module
gets loaded.

Tests that exercise real Postgres/Proxmox interactions are responsible for
providing their own fakes (see `test_intake_api.py` for the pattern).
"""

from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "postgresql://test/test")
os.environ.setdefault("PROXMOX_HOST", "test.invalid")
os.environ.setdefault("PROXMOX_USER", "test@pam")
os.environ.setdefault("PROXMOX_TOKEN_NAME", "test")
os.environ.setdefault("PROXMOX_TOKEN_VALUE", "test")
os.environ.setdefault("PROXMOX_NODE", "test")
os.environ.setdefault("CELERY_BROKER_URL", "memory://")
os.environ.setdefault("CELERY_RESULT_BACKEND", "cache+memory://")
