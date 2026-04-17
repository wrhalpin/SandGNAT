# OPNsense firewall configuration

The analysis network (`vmbr.analysis`, 192.168.100.0/24) is a default-deny
perimeter. OPNsense is the only bridge between it and anything else.

## Rule intent

```
Default: DENY (all interfaces, both directions)

Permitted inbound (from analysis VLAN -> OPNsense):
  - UDP 53   -> INetSim honeypot (192.168.100.2)
  - UDP 123  -> time server (192.168.100.2)
  - TCP 80   -> INetSim honeypot (192.168.100.2)
  - TCP 443  -> INetSim honeypot (192.168.100.2)
  - TCP 445  <- Job Orchestrator (192.168.100.1) only
  - TCP 3389 <- Job Orchestrator (192.168.100.1) only

Permitted outbound:
  - none. Host WAN uplinks must not appear in the analysis network routing table.

Drop silently (no ICMP unreachable):
  - Outbound to 172.16.0.0/24 (management)
  - Outbound to any RFC1918 space other than 192.168.100.0/24
  - Multicast, broadcast, link-local
```

## Files in this directory

- `rules.intent.md` (this file): human-authored policy.
- `rules.xml` (once authored): exported OPNsense config. Apply via Settings ->
  Backups -> Restore.

Treat `rules.xml` as the source of truth in prod, but edits should be made in
the OPNsense UI and re-exported here so the diff is reviewable.

## Kill switch

If a sandbox escape is suspected:

1. SSH to OPNsense.
2. `pfctl -d` disables the rule set — fails closed because of default-deny.
3. `qm stop` the analysis guest(s) from Proxmox.
4. Snapshot logs before revert.
