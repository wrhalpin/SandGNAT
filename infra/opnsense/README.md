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

Permitted from INetSim (192.168.100.2) -> upstream resolver (Phase F):
  - UDP 53   -> pinned public resolver (1.1.1.1 or 8.8.8.8) for the
               DNS whitelist only. No other protocol or destination.

Permitted outbound from analysis VLAN:
  - none. Host WAN uplinks must not appear in the analysis network routing table.
  - The upstream-resolver exception above is scoped to INetSim's IP,
    not the analysis VLAN broadly.

Drop silently (no ICMP unreachable):
  - Outbound to 172.16.0.0/24 (management)
  - Outbound to any RFC1918 space other than 192.168.100.0/24
  - Multicast, broadcast, link-local
```

## DNS whitelist (Phase F)

INetSim runs split-DNS: the names in `infra/inetsim/dns-whitelist.txt`
are forwarded to a pinned public resolver for a real A/AAAA answer;
every other query resolves to `192.168.100.2` (INetSim itself). The
corresponding OPNsense outbound rule is the only route off the
honeypot host.

**No TCP/UDP follow-up is allowed for whitelisted names** — the goal
is for `Resolve-DnsName microsoft.com` to return a realistic answer
while `Test-NetConnection microsoft.com -Port 443` still fails
closed.

See `infra/inetsim/README.md` for the config required on the INetSim
side.

## Traffic shaping (Phase F)

A zero-latency, zero-loss INetSim is itself a sandbox fingerprint.
The Proxmox host applies a `netem` qdisc to `vmbr.analysis`
(`infra/inetsim/netem.sh`, default: 25ms ±10ms jitter, 0.1% loss,
100 Mbit rate) so timing-sensitive checks see a residential-broadband
profile.

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
