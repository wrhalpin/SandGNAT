# Windows guest preparation

This directory holds PowerShell and batch scripts that run inside the analysis
VM template before the clean snapshot is taken. They are reference material —
operators apply them manually when baking a template; the orchestrator never
executes them on live samples.

## Workflow

1. Install Windows 10/11, patch fully.
2. Install FLARE-VM (`iex (iwr -useb https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1)`).
3. Run `disable-defender.ps1` and `disable-updates.ps1` to stabilise snapshot state.
4. Run `configure-capture.ps1` to lay down the capture directory (`C:\captures`),
   ProcMon config, and Wireshark profile.
5. Shut down cleanly and take the `clean` snapshot in Proxmox.

## Files (to be authored in Phase 2)

- `disable-defender.ps1`
- `disable-updates.ps1`
- `configure-capture.ps1`
- `collector-service/` — the Windows service that coordinates detonation and
  artifact collection under orchestrator control.

None of these scripts should be committed until they have been reviewed by
someone with Windows security-engineering signoff — they deliberately weaken
host protections and should not run outside the analysis VLAN.
