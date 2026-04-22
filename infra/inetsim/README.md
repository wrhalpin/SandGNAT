<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Bill Halpin
-->

# INetSim configuration for SandGNAT

Phase F of the anti-analysis mitigation plan
(`docs/explanation/anti-analysis-evasion.md`). INetSim (the honeypot
pinned at `192.168.100.2` on `vmbr.analysis`) is the only internet the
detonation guests are allowed to see. The default profile is too
obvious — single-byte responses to any URL, no NCSI magic string,
identical answer for `google.com` and `c2.evil.example` — so malware
that does even basic network triage flags the sandbox.

This directory ships the overrides SandGNAT applies on top of stock
INetSim to make the faux internet look real enough to pass lightweight
checks.

## Files

- `inetsim.conf` — the directives we override. Drop these into the
  INetSim VM's `/etc/inetsim/inetsim.conf` (or merge them with the
  site's existing conf; the lines are annotated).
- `dns-whitelist.txt` — list of ~50 domains whose **DNS** is answered
  by real recursive resolution through a pinned upstream. No TCP
  follow-up is permitted for these names (OPNsense rule).
- `netem.sh` — Proxmox-host script that applies realistic broadband
  jitter + loss to `vmbr.analysis`. Run at boot via systemd or a
  `@reboot` cron.
- `responses/` — curated HTTP/HTTPS response fixtures. Keyed by
  `host/path`; INetSim serves `responses/<host>/<path>` when a request
  matches.

## Rules of engagement

- **Whitelisted domains get DNS only.** Answers are real upstream
  responses; any subsequent TCP to the resolved IP is still dropped by
  OPNsense. The goal is for `nslookup microsoft.com` to return a real
  A record (passing the "is DNS working?" check) while guaranteeing
  nothing actually reaches Microsoft.
- **Everything else goes to INetSim.** A/AAAA responses all resolve
  to `192.168.100.2`, HTTP/HTTPS terminates there, and the response
  comes from `responses/` if a fixture matches the request, or from
  INetSim's default template if it doesn't.
- **No new outbound IP space.** The pinned upstream resolver must be
  reachable only from the INetSim VM, not from the analysis VLAN. The
  OPNsense rule allows port-53 egress from `192.168.100.2` to the
  pinned resolver IP, and nothing else.

## Adding a new response fixture

1. Drop the raw body into `responses/<host>/<path>`. For a bare host
   response (`/index.html`), place it at `responses/<host>/index.html`.
2. Re-sync to the INetSim VM:
   `rsync -a responses/ inetsim.analysis:/var/lib/inetsim/http/wwwroot/`
3. Restart the HTTPS plugin:
   `systemctl restart inetsim`
4. Verify from an analysis VM: `curl -sk https://<host>/<path>` should
   return the fixture body, not INetSim's default template.

## Validation

After applying everything in this directory:

```powershell
# From a detonation VM — should return "Microsoft NCSI".
curl.exe -sk https://www.msftncsi.com/ncsi.txt

# nslookup should return a real A record for whitelisted names.
nslookup microsoft.com

# …but no TCP follow-up should succeed.
Test-NetConnection microsoft.com -Port 443   # Expected: TcpTestSucceeded : False
```

Network-connectivity UI on Windows should treat the guest as online
and the "limited connectivity" flyout should never appear.
