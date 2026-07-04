# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Tests for ProxmoxClient teardown helpers (exists / destroy_if_exists).

These bypass __init__ (no live ProxmoxAPI) and patch the thin wrapper
methods, so we verify the orchestration logic — pre-clone cleanup ordering
and error tolerance — without a Proxmox cluster.
"""

from __future__ import annotations

from orchestrator.proxmox_client import GuestVM, ProxmoxClient


def _bare_client() -> ProxmoxClient:
    return ProxmoxClient.__new__(ProxmoxClient)


VM = GuestVM(vmid=9100, node="pve")


def test_exists_false_on_api_error(monkeypatch) -> None:
    c = _bare_client()

    def boom(_vm):
        raise RuntimeError("404 not found")

    monkeypatch.setattr(c, "status", boom)
    assert c.exists(VM) is False


def test_exists_true_when_status_returns(monkeypatch) -> None:
    c = _bare_client()
    monkeypatch.setattr(c, "status", lambda _vm: "running")
    assert c.exists(VM) is True


def test_destroy_if_exists_skips_when_absent(monkeypatch) -> None:
    c = _bare_client()
    calls: list[str] = []
    monkeypatch.setattr(c, "exists", lambda _vm: False)
    monkeypatch.setattr(c, "stop", lambda *a, **k: calls.append("stop"))
    monkeypatch.setattr(c, "destroy", lambda _vm: calls.append("destroy"))
    assert c.destroy_if_exists(VM) is False
    assert calls == []


def test_destroy_if_exists_stops_then_destroys(monkeypatch) -> None:
    c = _bare_client()
    calls: list = []
    monkeypatch.setattr(c, "exists", lambda _vm: True)
    monkeypatch.setattr(c, "stop", lambda _vm, **k: calls.append(("stop", k.get("force"))))
    monkeypatch.setattr(c, "wait_for_status", lambda _vm, s, **k: calls.append(("wait", s)))
    monkeypatch.setattr(c, "destroy", lambda _vm: calls.append("destroy"))
    assert c.destroy_if_exists(VM) is True
    # Force-stop, wait for stopped, then delete — in that order.
    assert calls == [("stop", True), ("wait", "stopped"), "destroy"]


def test_destroy_if_exists_deletes_even_if_stop_fails(monkeypatch) -> None:
    c = _bare_client()
    calls: list[str] = []
    monkeypatch.setattr(c, "exists", lambda _vm: True)

    def boom(*a, **k):
        raise RuntimeError("stop timed out")

    monkeypatch.setattr(c, "stop", boom)
    monkeypatch.setattr(c, "wait_for_status", lambda *a, **k: None)
    monkeypatch.setattr(c, "destroy", lambda _vm: calls.append("destroy"))
    # A leftover VM must still be deleted even when the stop step errors.
    assert c.destroy_if_exists(VM) is True
    assert calls == ["destroy"]
