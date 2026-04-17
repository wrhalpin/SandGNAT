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
4. After reboot, deploy the frozen guest agent (`sandgnat_guest_agent.exe`)
   to `C:\Tools\SandGNAT\sandgnat_guest_agent.exe`, then:
   ```powershell
   .\configure-capture.ps1 `
       -OrchestratorHost 192.168.100.1 `
       -AgentExePath "C:\Tools\SandGNAT\sandgnat_guest_agent.exe"
   ```
5. Reboot once more to confirm the scheduled task launches the agent.
   Verify by running `schtasks /query /tn SandGNATGuestAgent /v` — the task
   should be `Running`.
6. Stop the agent, clear `C:\captures\*` and `C:\sandgnat\*`, and from
   Proxmox take the `clean` snapshot. This is the snapshot every analysis
   reverts to.

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
