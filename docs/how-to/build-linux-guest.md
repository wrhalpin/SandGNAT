# How to build the Linux static-analysis guest

The Linux guest runs the pre-detonation static-analysis stage:
PE/ELF parsing, fuzzy hashing (ssdeep, TLSH), deep YARA, CAPA
capability detection, strings + entropy, and byte/opcode trigram
MinHashing. No sample execution, ever.

## Prerequisites

- A clean Debian 12 or Ubuntu 22.04 VM on Proxmox. 2–4 GiB RAM,
  2 vCPU, 20 GiB disk, on the analysis bridge.
- Python 3.11+.
- Network access during prep only (for apt + pip installs). The
  analysis-bridge firewall rules lock this down after.

## Base image

Install the VM with the minimal netinst image. Apt the basics:

```bash
apt-get update
apt-get install -y \
    python3.11 python3-pip python3-venv \
    yara libyara-dev \
    ssdeep libfuzzy-dev \
    libtlsh-dev \
    git ca-certificates
```

Install CAPA from upstream releases (it's Go, so just one binary):

```bash
curl -LO https://github.com/mandiant/capa/releases/latest/download/capa-linux.zip
unzip capa-linux.zip -d /usr/local/bin/
chmod +x /usr/local/bin/capa
capa --version  # verify
```

## Deploy the guest package

Unlike the Windows guest, the Linux guest doesn't need a freeze step —
it runs under the system Python interpreter.

```bash
# Clone and install.
git clone https://github.com/wrhalpin/SandGNAT /opt/sandgnat
cd /opt/sandgnat
python3.11 -m venv /opt/sandgnat/venv
/opt/sandgnat/venv/bin/pip install -e '.[static]'
```

The `[static]` extra pulls in `pefile`, `pyelftools`, `ssdeep`,
`python-tlsh`, `capstone`, and `yara-python`. Missing ones degrade
to skipped at runtime — the guest won't crash without them.

## Mount the staging share

The guest needs `/srv/sandgnat/staging` to point at the same SMB/NFS
share the orchestrator writes to.

```bash
# /etc/fstab entry for SMB:
//orchestrator.internal/sandgnat  /srv/sandgnat/staging  cifs  credentials=/etc/sandgnat/smb.cred,uid=sandgnat,gid=sandgnat,_netdev  0 0

# Or NFS:
orchestrator.internal:/srv/sandgnat  /srv/sandgnat/staging  nfs  defaults,_netdev  0 0
```

Verify read+write:

```bash
sudo -u sandgnat ls /srv/sandgnat/staging
sudo -u sandgnat touch /srv/sandgnat/staging/completed/.write-test && \
    rm /srv/sandgnat/staging/completed/.write-test
```

## Deep-YARA rules

Mount or sync the deep ruleset onto the guest — conventionally at
`/etc/sandgnat/yara-deep`. See
[configure-yara.md](configure-yara.md).

## Environment

`/etc/sandgnat/env`:

```bash
LINUX_GUEST_STAGING_ROOT=/srv/sandgnat/staging
LINUX_GUEST_POLL_INTERVAL=2.0
LINUX_GUEST_CAPA_EXE=/usr/local/bin/capa
LINUX_GUEST_YARA_DEEP_RULES_DIR=/etc/sandgnat/yara-deep
LINUX_GUEST_MAX_STRINGS_BYTES=1048576
```

## systemd unit

`/etc/systemd/system/sandgnat-static.service`:

```ini
[Unit]
Description=SandGNAT Linux static-analysis guest
After=network-online.target remote-fs.target
Wants=network-online.target remote-fs.target

[Service]
Type=simple
User=sandgnat
Group=sandgnat
EnvironmentFile=/etc/sandgnat/env
ExecStart=/opt/sandgnat/venv/bin/python -m linux_guest_agent
Restart=on-failure
RestartSec=5s
# Tightened sandboxing: we only read samples and write artifacts.
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/srv/sandgnat/staging
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

Enable:

```bash
useradd -r -s /bin/false sandgnat
chown -R sandgnat:sandgnat /opt/sandgnat
systemctl daemon-reload
systemctl enable --now sandgnat-static.service
journalctl -u sandgnat-static -f
```

## Take the clean snapshot

Same flow as the Windows guest:

1. Stop the service: `systemctl stop sandgnat-static.service`.
2. Clean any pending samples: `rm -rf /srv/sandgnat/staging/in-flight/*`
   (on the host; shouldn't be any if you only used this VM for prep).
3. From the Proxmox host:

   ```bash
   qm snapshot 9001 clean --description "Debian 12 + SandGNAT static guest ready"
   ```

The Linux pool clones from vmid 9001 (`LINUX_TEMPLATE_VMID`) and
reverts to `clean` after each job.

## Test the template

```python
# On the orchestrator host:
from uuid import uuid4
from pathlib import Path
from orchestrator.schema import MODE_STATIC_ANALYSIS, StaticAnalysisOptions
from orchestrator.guest_driver import submit_job, wait_for_result

job_id = uuid4()
# Stage a benign test sample first — e.g. /bin/ls from the guest or any small ELF.
# Put it at {staging}/samples/{job_id}/ls
submit_job(
    Path("/srv/sandgnat/staging"), job_id,
    sample_name="ls", sample_sha256="<sha256>",
    timeout_seconds=60, mode=MODE_STATIC_ANALYSIS,
    static=StaticAnalysisOptions(),
)
art = wait_for_result(Path("/srv/sandgnat/staging"), job_id, timeout_seconds=120)
print(art.envelope.status, art.envelope.static_summary)
```

Expect `status=="completed"` and `static_summary["file_format"] == "elf64"`
for a typical binary.

## Troubleshooting

- **Service fails to start with "yara-python missing"** — optional,
  not fatal. Check `journalctl -u sandgnat-static` for the actual
  error. A genuine crash is something else.
- **CAPA times out** — CAPA is slow on stripped binaries.
  `StaticAnalysisOptions.per_tool_timeout_seconds` caps it at 120 s
  by default; bump if needed or disable CAPA for specific submissions.
- **`pefile` crashes on exotic PE** — degrades to `skipped: true`
  with the exception message. Other tools still run. If it's a
  persistent pattern, open an issue; pefile bugs are usually quick
  fixes upstream.
- **Trigram output missing** — check `static_analysis.json` → `trigrams`
  section on the host. If `opcode_skipped_reason` is set, capstone
  didn't recognise the architecture. Byte trigrams should still work.
- **Guest refuses job with "mode='detonation'"** — somebody published
  a detonation manifest to a Linux pool. Check pool ranges and the
  task wiring; typically a misconfiguration of
  `LINUX_VM_POOL_VMID_MIN/MAX`.

## Upgrading

The Linux guest doesn't need a refreeze — it's interpreted. For a
code update:

```bash
cd /opt/sandgnat
git pull
/opt/sandgnat/venv/bin/pip install -e '.[static]'
systemctl restart sandgnat-static
```

Re-take the snapshot after verifying it comes up clean.

## Related

- [build-windows-guest.md](build-windows-guest.md) — detonation
  counterpart.
- [configure-yara.md](configure-yara.md) — deep-rule setup.
- [tune-vm-pools.md](tune-vm-pools.md) — Windows vs Linux pool sizing.
