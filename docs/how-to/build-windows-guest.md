# How to build the Windows detonation guest

The Windows guest polls the staging share, claims jobs with
`mode=detonation`, and runs ProcMon / tshark / RegShot plus the
sample itself inside a disposable Windows VM. This guide covers the
VM template, the frozen guest binary, and the Proxmox snapshot workflow.

## Prerequisites

- A clean Windows 10 22H2 or Windows 11 VM on Proxmox. 4–8 GiB RAM,
  2–4 vCPU, 60–80 GiB disk, on the analysis bridge.
- `FLARE-VM` installed (includes ProcMon, tshark, RegShot, Process
  Explorer, and friends). See flare-vm.github.io for the installer.
- Python 3.11 **on the VM** for the PyInstaller freeze step. Only
  needed at build time; the frozen exe has no runtime Python
  dependency.

## VM hardening

Before taking the "clean" snapshot, apply:

- `infra/guest/disable-defender.ps1` — disables Windows Defender,
  SmartScreen, real-time protection. Malware sees the real OS without
  its own detection interference.
- `infra/guest/disable-updates.ps1` — disables Windows Update so the
  snapshot state is stable.
- `infra/guest/configure-capture.ps1` — maps the SMB staging share,
  registers the guest-agent scheduled task, installs firewall rules.

Review those scripts before running them — they deliberately weaken
the VM's posture. Read [isolation-model.md](../explanation/isolation-model.md)
for the threat model.

## Build the guest agent binary

On a **build machine** (your dev laptop or a CI runner) running
Windows with Python 3.11:

```powershell
git clone https://github.com/wrhalpin/SandGNAT
cd SandGNAT
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .
pip install pyinstaller

# Freeze:
pyinstaller --onefile --name sandgnat-guest `
    --hidden-import=orchestrator.schema `
    guest_agent/__main__.py

# Output: dist/sandgnat-guest.exe
```

The guest is stdlib-only (plus `orchestrator.schema`), so the
PyInstaller bundle is ~10 MiB. No wheels, no C extensions, no
surprises.

## Deploy to the template VM

1. Copy `dist/sandgnat-guest.exe` to the VM (RDP + drag-drop, or via
   the Proxmox mgmt interface before first boot).
2. Place it somewhere stable, e.g. `C:\Program Files\SandGNAT\sandgnat-guest.exe`.
3. Register the scheduled task that starts it at boot:

   ```powershell
   # See infra/guest/configure-capture.ps1 for the exact command.
   Register-ScheduledTask -TaskName SandGNATGuest `
       -Action (New-ScheduledTaskAction -Execute 'C:\Program Files\SandGNAT\sandgnat-guest.exe') `
       -Trigger (New-ScheduledTaskTrigger -AtStartup) `
       -Principal (New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -RunLevel Highest)
   ```

## Configure env vars

Set via `setx /M` (machine-level):

```cmd
setx /M SANDGNAT_STAGING_ROOT "\\orchestrator\sandgnat"
setx /M SANDGNAT_POLL_INTERVAL 2.0
setx /M SANDGNAT_PROCMON_EXE  "C:\Tools\Procmon\Procmon.exe"
setx /M SANDGNAT_TSHARK_EXE   "C:\Program Files\Wireshark\tshark.exe"
setx /M SANDGNAT_REGSHOT_EXE  "C:\Tools\Regshot\Regshot-x64.exe"
setx /M SANDGNAT_CAPTURE_INTERFACE "Ethernet"
```

(The exact env var names are in `guest_agent/config.py`.)

## Take the clean snapshot

1. Reboot the VM. Confirm the scheduled task started `sandgnat-guest.exe`
   (Task Manager → Services / Processes).
2. Stop the guest: `net stop SandGNATGuest` (or just kill the PID if
   it was started as a task not a service). This is important —
   snapshotting with the guest running captures its in-memory state,
   which usually isn't what you want.
3. From the Proxmox host:

   ```bash
   qm snapshot 9000 clean --description "FLARE-VM + SandGNAT guest ready"
   ```

That snapshot is what every detonation clones from.

## Test the template

Before declaring the template ready:

1. Start the VM. Verify the guest comes up automatically.
2. From the orchestrator, publish a test manifest:

   ```python
   from uuid import uuid4
   from pathlib import Path
   from orchestrator.schema import MODE_DETONATION
   from orchestrator.guest_driver import submit_job, wait_for_result

   job_id = uuid4()
   # Drop a tiny benign EXE at the expected path first.
   submit_job(
       Path("/srv/sandgnat/staging"), job_id,
       sample_name="test.exe", sample_sha256="deadbeef" * 8,
       timeout_seconds=60, mode=MODE_DETONATION,
   )
   artifacts = wait_for_result(Path("/srv/sandgnat/staging"), job_id, timeout_seconds=120)
   print(artifacts.envelope.status)
   ```

3. Expect `artifacts.envelope.status == "completed"` (or `"failed"`
   with an explanatory `errors` field if the test binary didn't run —
   that's fine, it proves the plumbing works).
4. Revert the VM to `clean` between test runs.

## Upgrading the guest binary

Schema bumps (e.g. 1→2 in Phase 4) require re-freezing. Workflow:

1. Build the new exe.
2. Boot the template, stop the old guest, replace the exe, start the
   guest.
3. **Re-take the snapshot** (`qm snapshot 9000 clean --force`).
4. Every detonation clone from that point forward uses the new guest.

If you skip the snapshot, clones still use the old guest.

## Troubleshooting

- **Guest claims a job but never writes result.json.** Check the
  guest's Windows Event Log for crashes. ProcMon/tshark/RegShot need
  to be at their configured paths.
- **Staging share isn't writable.** The SMB mount on the VM side
  needs write permission for whatever user the guest runs as. If the
  guest runs as SYSTEM, map the share via `cmdkey` so SYSTEM has the
  credentials.
- **Sample can't be read.** Check that
  `C:\sandgnat\{analysis_id}\{sample_name}` resolves to
  `{staging_root}/samples/{analysis_id}/{sample_name}` on the host.
  The path mapping is configured in `configure-capture.ps1`.
- **ProcMon CSV is truncated.** ProcMon's ring buffer fills. Increase
  the backing file size in `guest_agent/capture/procmon.py` or reduce
  the filter scope.
- **Mode-mismatch errors.** "Refusing job X: mode='static_analysis'"
  means a Linux-destined job was mis-routed. Check `tasks_static`
  config and the pool ranges — the Linux pool should be 9200–9299,
  Windows 9100–9199 by default, with no overlap.

## Related

- [build-linux-guest.md](build-linux-guest.md) — the static-analysis
  counterpart.
- [reference/wire-protocol.md](../reference/wire-protocol.md) — the
  host↔guest contract.
- [tune-vm-pools.md](tune-vm-pools.md) — sizing Windows vs Linux pools.
