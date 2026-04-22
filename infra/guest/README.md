# Windows guest preparation

Scripts and collateral for baking the analysis-VM template. Operators run
these manually during template creation; the orchestrator never executes
them against live samples.

## One-time template workflow

1. Install Windows 10/11, fully patch, log in as `Analyst` (local admin).
2. Install FLARE-VM (see `https://github.com/mandiant/flare-vm`).
3. From an elevated PowerShell:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\disable-defender.ps1
   .\disable-updates.ps1
   # Restart so UAC / service changes take effect.
   Restart-Computer
   ```
4. After reboot, seed the decoy user profile (Phase B of the
   anti-analysis plan). Stage realistic `Documents/`, `Downloads/`,
   and `Pictures/` content into `infra/guest/seed-data/` beforehand —
   see that directory's README for guidance — then:
   ```powershell
   .\seed-user-profile.ps1
   # Records generated credentials in C:\Users\<user>\profile.seed.json.
   ```
   Note the generated username; the capture script needs it in the
   next step.
5. Deploy the frozen guest agent (`sandgnat_guest_agent.exe`) to
   `C:\Tools\SandGNAT\sandgnat_guest_agent.exe`, then configure capture
   (Phase C renames ProcMon to `C:\Windows\System32\SystemAudit.exe`
   and registers the scheduled task as `Windows-PowerManagementAudit`):
   ```powershell
   .\configure-capture.ps1 `
       -OrchestratorHost 192.168.100.1 `
       -AgentExePath "C:\Tools\SandGNAT\sandgnat_guest_agent.exe" `
       -UserName emily.carter
   ```
6. Reboot once more to confirm the scheduled task launches the agent
   and the seeded user autologs on. Verify by running
   `schtasks /query /tn Windows-PowerManagementAudit /v` — the task
   should be `Running`.
7. Stop the agent, clear the workspace
   (`C:\Users\<user>\AppData\Local\Microsoft\PowerManagement\`) and
   its `captures\` subdirectory, and from Proxmox take the `clean`
   snapshot. This is the snapshot every analysis reverts to.

## Template sizing baseline

Malware increasingly keys off resource shape (under-4 vCPUs and
under-6 GB RAM are the most-cited "too small for a real desktop"
thresholds). Match these defaults when provisioning the template:

| Resource   | Default             | Minimum |
|------------|---------------------|---------|
| vCPUs      | 4 cores × 2 threads | 4       |
| RAM        | 8 GB                | 6 GB    |
| Disk       | 120 GB              | 80 GB   |
| Resolution | 1920×1080           | 1600×900 |

Headroom matters more than raw count — a 2-core VM with 80 GB of empty
disk still flags; a 4-core VM with a filled 80 GB disk doesn't.

## Freezing the guest agent

The agent lives in the root repo at `guest_agent/`. Build the frozen exe on
a Windows dev machine:

```powershell
python -m pip install pyinstaller
pyinstaller --onefile --name sandgnat_guest_agent `
    --paths . guest_agent\__main__.py
```

`orchestrator/schema.py` is pulled in automatically because the agent
imports it; nothing else from the orchestrator package is reachable from
the agent entry point, so the bundle stays small.

## Safety notes

- All scripts deliberately weaken host protections. They must only run on
  VMs attached to `vmbr.analysis` (default-deny egress).
- Never commit a template VHD/QCOW2 to this repo.
- `configure-capture.ps1` blocks all outbound and allows only inbound SMB
  from the orchestrator — this is belt-and-suspenders beside the VLAN
  firewall, not a replacement for it.
