# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Thin wrapper over proxmoxer for the VM lifecycle we actually use.

We intentionally expose a narrow surface: clone-from-template, revert, start,
stop, wait-for-status. That's everything `tasks.py` needs and keeps the mock
surface small for tests.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from proxmoxer import ProxmoxAPI

from .config import ProxmoxConfig, get_settings


@dataclass(slots=True)
class GuestVM:
    """Identifies one live VM on the Proxmox cluster by its vmid + node."""

    vmid: int
    node: str


class ProxmoxClient:
    """Narrow proxmoxer wrapper covering only what the Celery tasks need:
    clone-from-template, revert, start/stop, status polling.

    Kept small so tests can mock a single object instead of the full
    proxmoxer surface.
    """

    def __init__(self, config: ProxmoxConfig | None = None) -> None:
        self._cfg = config or get_settings().proxmox
        self._api = ProxmoxAPI(
            self._cfg.host,
            user=self._cfg.user,
            token_name=self._cfg.token_name,
            token_value=self._cfg.token_value,
            verify_ssl=self._cfg.verify_ssl,
        )

    # -- VM lifecycle --------------------------------------------------------

    def clone_from_template(self, new_vmid: int, name: str) -> GuestVM:
        """Linked-clone the template snapshot into `new_vmid`."""
        node = self._api.nodes(self._cfg.node)
        node.qemu(self._cfg.template_vmid).clone.post(
            newid=new_vmid,
            name=name,
            snapname=self._cfg.clean_snapshot,
            full=0,  # linked clone — fast and disposable
        )
        return GuestVM(vmid=new_vmid, node=self._cfg.node)

    def revert_snapshot(self, vm: GuestVM, snapshot: str | None = None) -> None:
        """Roll `vm` back to the clean snapshot (or a named one)."""
        snap = snapshot or self._cfg.clean_snapshot
        self._api.nodes(vm.node).qemu(vm.vmid).snapshot(snap).rollback.post()

    def start(self, vm: GuestVM) -> None:
        """Power on `vm`."""
        self._api.nodes(vm.node).qemu(vm.vmid).status.start.post()

    def stop(self, vm: GuestVM, *, force: bool = False) -> None:
        """Power off `vm`: graceful shutdown, or hard-stop when `force=True`."""
        endpoint = self._api.nodes(vm.node).qemu(vm.vmid).status
        (endpoint.stop if force else endpoint.shutdown).post()

    def destroy(self, vm: GuestVM) -> None:
        """Delete the VM definition. Used for disposable clones after use."""
        self._api.nodes(vm.node).qemu(vm.vmid).delete()

    # -- Status --------------------------------------------------------------

    def status(self, vm: GuestVM) -> str:
        """Return Proxmox's current status string ('running', 'stopped', ...)."""
        data = self._api.nodes(vm.node).qemu(vm.vmid).status.current.get()
        return str(data.get("status", "unknown"))

    def wait_for_status(
        self, vm: GuestVM, desired: str, *, timeout: float = 120.0, poll_interval: float = 2.0
    ) -> None:
        """Block until `vm` reports `desired` status. Raises `TimeoutError`."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.status(vm) == desired:
                return
            time.sleep(poll_interval)
        raise TimeoutError(f"VM {vm.vmid} did not reach status={desired!r} in {timeout}s")
