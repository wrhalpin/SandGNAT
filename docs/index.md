---
layout: default
title: SandGNAT
description: Automated malware runtime-analysis sandbox. STIX 2.1 native, trigram-clustered, Proxmox-isolated.
---

<div style="display: flex; align-items: center; gap: 2.5rem; margin-bottom: 2rem;">
  <div style="flex: 1; min-width: 0;">
    <p style="margin: 0 0 .35rem 0; font-size: .95rem; color: #606c71; text-transform: uppercase; letter-spacing: .06em;">GNAT-o-sphere / malware sandbox</p>
    <h1 style="margin-top: 0;">SandGNAT</h1>
    <p>Automated malware runtime-analysis environment: detonate suspicious
    binaries in isolated Windows VMs on Proxmox, cluster samples against
    the existing corpus via byte/opcode trigram MinHash, and emit STIX 2.1
    objects into PostgreSQL.</p>
    <p>Source: <a href="https://github.com/wrhalpin/SandGNAT"><code>github.com/wrhalpin/SandGNAT</code></a>.</p>
  </div>
  <div style="flex-shrink: 0;">
    <img src="assets/logo/sandgnat-logo-512.png"
         alt="SandGNAT mascot"
         width="300">
  </div>
</div>

---

## Documentation

Organised with the [Diátaxis](https://diataxis.fr/) framework. Four
quadrants for four kinds of reader-intent:

|                | **Action (doing)**              | **Study (reading)**            |
|----------------|---------------------------------|--------------------------------|
| **Learning**   | [Tutorials](tutorials/)         | [Explanation](explanation/)    |
| **Working**    | [How-to guides](how-to/)        | [Reference](reference/)        |

### Start here if you're…

- **New to SandGNAT** → [tutorials/01 — Your first sample](tutorials/01-your-first-sample.md)
- **Standing up a dev stack** → [tutorials/02 — Local dev stack](tutorials/02-local-dev-stack.md)
- **Curious about the architecture** → [explanation/architecture](explanation/architecture.md)
- **Integrating the export API** → [reference/http-api](reference/http-api.md)

## What SandGNAT does, end to end

1. **Intake** (`POST /submit`) — validate, hash, dedupe against the
   existing corpus, VT hash pre-check, YARA scan, stage to SMB.
2. **Static analysis** (Linux VM, optional pre-stage) — PE/ELF parsing,
   ssdeep + TLSH fuzzy hashes, deep YARA, CAPA capability detection,
   strings + entropy, byte + opcode trigram MinHash.
3. **LSH similarity lookup** — banded-candidate fetch then exact Jaccard.
   If the best hit clears the threshold (default 0.85), skip detonation.
4. **Windows detonation** — ProcMon, tshark, RegShot, dropped-file collection.
5. **Artifact parsing → STIX 2.1** — deterministic UUIDv5 IDs, PostgreSQL
   JSONB storage.
6. **Export** — `GET /analyses/<uuid>/bundle` serves the STIX bundle to
   external consumers (the [GNAT][gnat] connector, analyst scripts, etc.).

[gnat]: https://github.com/wrhalpin/GNAT

Full architecture diagrams live in
[explanation/architecture](explanation/architecture.md) — topology,
pipeline flow, sequence, and component diagrams rendered via Mermaid.

## Key design choices

- **Isolation by default.** Analysis bridge has no host IP. OPNsense
  default-denies egress; only INetSim and staging SMB are allowed. See
  [explanation/isolation-model](explanation/isolation-model.md).
- **STIX 2.1 as the output contract.** Survives schema churn, plays
  nicely with every modern TIP. Rationale: [explanation/why-stix](explanation/why-stix.md).
- **Byte + opcode trigram MinHash + LSH bands.** Sub-linear similarity
  lookup over a growing corpus. Theory: [explanation/similarity](explanation/similarity.md).
- **Near-duplicate short-circuit.** Skip detonation when a submission is
  obviously a repacked variant of something we already analysed. Details:
  [explanation/near-duplicate-short-circuit](explanation/near-duplicate-short-circuit.md).

- **Anti-analysis evasion posture.** Catalogue of how modern malware
  detects sandboxes plus the phased mitigation plan for SandGNAT:
  [explanation/anti-analysis-evasion](explanation/anti-analysis-evasion.md).

## Status

Phases 1–6 shipped: scaffold, host↔guest detonation protocol, intake,
VM pool manager, Linux static-analysis + trigram similarity, the
read-only export API, and the anti-analysis evasion mitigations
(phases A–G). See
[explanation/anti-analysis-evasion](explanation/anti-analysis-evasion.md)
for the full implementation record.

## The GNAT-o-sphere

SandGNAT is one of three add-ons that plug into **GNAT**, the core
threat-intel platform. Every sibling emits STIX 2.1 objects and is
pulled by GNAT through a documented connector rather than writing
into its database directly.

[Canonical workflow documentation →](https://wrhalpin.github.io/gnat-o-sphere/workflow.html)

<div style="display: flex; flex-wrap: wrap; gap: 1rem; margin-top: 1.25rem; align-items: stretch;">

  <div style="flex: 1 1 240px; background: #fafafa; border: 2px solid #C41E2A; border-radius: 14px; padding: 1.5rem 1.25rem; display: flex; flex-direction: column;">
    <span style="font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; color: #606c71; margin-bottom: .5rem;">Core platform</span>
    <h3 style="margin: 0 0 .5rem 0; color: #C41E2A; font-size: 1.25rem;">GNAT</h3>
    <p style="flex: 1; margin: 0;">The hub TIP. Connector abstraction, STIX 2.1 modelling, investigations, reports, and workflow automation across a large integration surface.</p>
    <a href="https://wrhalpin.github.io/GNAT/" style="display: inline-block; margin-top: .75rem; padding: .4rem 1rem; border-radius: 8px; font-size: .9rem; font-weight: 600; text-decoration: none; color: #fff; background: #C41E2A; align-self: flex-start;">Learn more</a>
  </div>

  <div style="flex: 1 1 240px; background: #fafafa; border: 2px solid #C0392B; border-radius: 14px; padding: 1.5rem 1.25rem; display: flex; flex-direction: column;">
    <span style="font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; color: #606c71; margin-bottom: .5rem;">Addon</span>
    <h3 style="margin: 0 0 .5rem 0; color: #C0392B; font-size: 1.25rem;">RedGNAT</h3>
    <p style="flex: 1; margin: 0;">Continuous automated red teaming — ingests threat intel, constructs adversary emulation scenarios, executes them with safety controls.</p>
    <a href="https://wrhalpin.github.io/RedGNAT/" style="display: inline-block; margin-top: .75rem; padding: .4rem 1rem; border-radius: 8px; font-size: .9rem; font-weight: 600; text-decoration: none; color: #fff; background: #C0392B; align-self: flex-start;">Learn more</a>
  </div>

  <div style="flex: 1 1 240px; background: #fafafa; border: 2px solid #7C3AED; border-radius: 14px; padding: 1.5rem 1.25rem; display: flex; flex-direction: column;">
    <span style="font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; color: #606c71; margin-bottom: .5rem;">Addon</span>
    <h3 style="margin: 0 0 .5rem 0; color: #7C3AED; font-size: 1.25rem;">SenseGNAT</h3>
    <p style="flex: 1; margin: 0;">Network sensor + honeypot telemetry. High-volume Kafka ingestion, Redis dedupe, automatic campaign linking back into GNAT.</p>
    <a href="https://wrhalpin.github.io/SenseGNAT/" style="display: inline-block; margin-top: .75rem; padding: .4rem 1rem; border-radius: 8px; font-size: .9rem; font-weight: 600; text-decoration: none; color: #fff; background: #7C3AED; align-self: flex-start;">Learn more</a>
  </div>

</div>

Licensed under [Apache 2.0](https://github.com/wrhalpin/SandGNAT/blob/main/LICENSE).
