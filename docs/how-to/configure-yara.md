# How to configure YARA rules

SandGNAT has **two** independent YARA scan points:

1. **Intake-time quick scan** (`INTAKE_YARA_RULES_DIR`) — runs on the
   orchestrator against every submission before enqueue. Matches bump
   priority and annotate the job.
2. **Deep scan on the Linux static-analysis guest**
   (`STATIC_YARA_DEEP_RULES_DIR` on the host;
   `LINUX_GUEST_YARA_DEEP_RULES_DIR` on the guest) — runs as part of
   the static stage with a heavier ruleset.

Both use `yara-python`. Both are optional: a missing library or an
empty rules directory degrades to a no-op.

## When to use which

- **Intake quick scan**: fast, cheap, run on every submission. Good
  for known-family fingerprints, triage tags, and obvious-badness
  rules that should bump priority immediately.
- **Deep scan**: slower, runs in the isolated VM. Good for rules that
  touch many strings, use imports (`pe.imphash` etc.), or need the
  capstone-disassembled view.

They're independent; you can run both, either, or neither.

## Install `yara-python`

The intake path needs the `yara` optional extra:

```bash
pip install -e '.[yara]'
```

`yara-python` bundles libyara by default on Linux but fails at
install-time if your toolchain is unhappy. If you see "libyara.so not
found," your distro probably ships a separate libyara package:

```bash
# Debian/Ubuntu:
apt-get install libyara-dev yara
```

On the Linux static-analysis guest, the tool wrapper imports
`yara-python` lazily and degrades to skipped if missing — so a guest
without libyara still works, the deep scan just doesn't run.

## Configure rule directories

**On the orchestrator** (intake + export):

```bash
INTAKE_YARA_RULES_DIR=/etc/sandgnat/yara-intake
STATIC_YARA_DEEP_RULES_DIR=/etc/sandgnat/yara-deep
```

**On the Linux static-analysis guest**:

```bash
LINUX_GUEST_YARA_DEEP_RULES_DIR=/etc/sandgnat/yara-deep
```

(You'll typically mount the same rules volume on both host and guest
via a shared filesystem; see [build-linux-guest.md](build-linux-guest.md).)

Both directories are scanned recursively for `*.yar` / `*.yara`
files. Every rule file is compiled once at service start; compile
errors surface at boot, not at first sample.

## Writing rules that SandGNAT cares about

Intake promotes priority (`prioritized` decision, `priority ≤ 2`) for:

- Rules with a `meta.severity` of `"high"` or `"critical"`.
- Rules tagged with any of `malware`, `apt`, `ransomware`, `rat`,
  `stealer`.

Everything else is matched and recorded but doesn't bump priority.

Example "high-severity" rule that would promote:

```yara
rule EvilCorp_Stealer_v3 : stealer malware
{
    meta:
        author = "your-analyst"
        severity = "high"
        description = "Known EvilCorp credential-stealer variant v3"

    strings:
        $config_magic = "ECSC3" wide
        $c2_pattern = /\bec[a-z0-9]{3,}\.example\b/

    condition:
        $config_magic and $c2_pattern
}
```

An "advisory" rule that would just annotate:

```yara
rule High_Entropy_Code_Section
{
    meta:
        severity = "info"
        description = "Code section entropy suggests packing"

    condition:
        math.entropy(filesize - 1024, 1024) >= 7.0
}
```

## Deep-scan rules

The deep scan is free to use heavier features:

- `pe` module (`pe.imphash`, `pe.imports`) — the quick scan runs on
  raw bytes too, so these work there, but PE-based rules match nothing
  on ELFs and vice versa.
- Large string sets — compile time grows with the rule count, but
  scan time is bounded by the VM's CPU time.

If you have vendor-licensed rulesets (e.g. from a threat-intel feed),
put them in the deep dir — they're typically too heavy for every
intake.

## Verify rules loaded

Check the intake-service logs at startup. You should see:

    INFO orchestrator.yara_scanner: Compiling 14 YARA rule files from /etc/sandgnat/yara-intake

(The number is the count of distinct rule files, not individual rules.)

Submit a known-bad sample and verify the `/submit` response:

```json
{
  "decision": "prioritized",
  "priority": 2,
  "yara_matches": [
    {"rule": "EvilCorp_Stealer_v3", "tags": ["stealer", "malware"], "meta": {"severity": "high"}}
  ]
}
```

And in the DB:

```sql
SELECT yara_matches FROM analysis_jobs WHERE id = '...';
```

## Failure modes

- **Rule file with a syntax error** — compile fails at service start
  with a logged error; the scanner falls back to disabled. Fix the
  file and restart.
- **Rule file with the same name but different content on two hosts** —
  intake and deep scans are independent; rules don't have to match.
  For reproducibility, source both directories from the same
  canonical store (git, NFS).
- **YARA runtime error on a specific sample** — logged at WARNING,
  scan returns empty matches for that sample only. Intake still
  enqueues the job.

## Managing rules

SandGNAT has no opinion about how you maintain the rules directory.
Common patterns:

- **Git repo** — one repo per rule class (intake-quick vs deep), CI
  that runs `yara -c` to validate syntax before merge. Deploy via
  `git pull` on the host and guest.
- **Shared NFS mount** — same directory mounted on host and guest.
  Simplest for small teams; relies on the NFS being up.
- **Bundled into a container image** — rules baked into the
  orchestrator image, versioned with the service. Great for
  reproducibility; slow for rule iteration.

## Security

- Rule files are executed (compiled and matched). A malicious rule
  file could trigger bugs in libyara and potentially achieve code
  execution on the scanner. Keep your rule sources trusted.
- Don't load rules directly from sample submissions or any untrusted
  input — they go in the sample pile, not the rules directory.
- The intake YARA scanner runs on the orchestrator host, not inside a
  VM. That's deliberate — it's a cheap triage signal — but it does
  mean libyara's attack surface is on your orchestrator. Keep
  yara-python patched.
