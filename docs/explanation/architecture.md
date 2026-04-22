# Architecture overview

SandGNAT is a malware runtime-analysis sandbox. It takes a binary,
detonates it inside an isolated Windows VM, captures behavioural
artifacts (registry, filesystem, network, processes), and emits STIX
2.1 into PostgreSQL. A pre-detonation Linux static-analysis stage
clusters new submissions against known ones and skips detonation when a
new sample is a near-duplicate of something already analysed.

This page is the anchor for the "how does it fit together" question.
For the canonical design-of-record see
[`MALWARE_ANALYSIS_SYSTEM_DESIGN.md`](../MALWARE_ANALYSIS_SYSTEM_DESIGN.md).

## Infrastructure topology

```mermaid
flowchart TB
    subgraph Proxmox["Proxmox host"]
        direction TB
        subgraph MgmtBr["Management bridge (vmbr0)"]
            Orchestrator["Job Orchestrator VM<br/>Celery + intake/export API"]
            Postgres["PostgreSQL VM<br/>STIX, jobs, signatures"]
            Redis["Redis VM<br/>Celery broker"]
        end
        subgraph AnalysisBr["Analysis bridge (vmbr.analysis)<br/>no IP on host"]
            Firewall["OPNsense firewall<br/>default-deny"]
            Windows1["Windows VM<br/>vmid 9100..9199"]
            Windows2["Windows VM"]
            Linux1["Linux static VM<br/>vmid 9200..9299"]
            Linux2["Linux static VM"]
            INetSim["INetSim<br/>fake DNS/HTTP"]
        end
        SMB[("SMB / NFS staging share")]
        Quarantine[("Quarantine store<br/>immutable, append-only")]
    end

    User((Analyst)) -->|POST /submit| Orchestrator
    GNAT((GNAT connector)) -->|GET /analyses/...| Orchestrator

    Orchestrator --> Redis
    Orchestrator --> Postgres
    Orchestrator --> SMB
    Orchestrator -.Proxmox API.-> Windows1
    Orchestrator -.Proxmox API.-> Linux1

    Windows1 -.polls staging.-> SMB
    Linux1 -.polls staging.-> SMB
    Windows1 -->|egress| Firewall
    Firewall --> INetSim

    Orchestrator --> Quarantine
```

Key isolation points:

- `vmbr.analysis` has no IP on the Proxmox host, so the host is
  unreachable from any analysis VM.
- OPNsense default-denies everything outbound; the only permitted egress
  is to INetSim (fake DNS/HTTP) and the orchestrator's SMB share.
- Windows detonation VMs get no unrestricted internet. Malware's C2
  traffic is redirected to INetSim so we observe the indicators without
  exfiltration risk.
- The orchestrator and analysis VMs never share a bridge with untrusted
  networks.

See [isolation-model.md](isolation-model.md) for the full threat model.

## Pipeline shape

A single submission traverses four stages: intake validates and stages
the sample, optionally static analysis runs first, detonation captures
dynamic behaviour, and export exposes the result to downstream
consumers.

```mermaid
flowchart LR
    Start([POST /submit]) --> Validate[Validate size + hash + dedupe]
    Validate -->|reject| Rejected([400 rejected])
    Validate -->|duplicate| Duplicate([200 duplicate])
    Validate --> VT[VT hash lookup]
    VT --> YARA[YARA scan]
    YARA --> Insert[(Insert analysis_jobs)]
    Insert --> Stage[Stage bytes to SMB share]
    Stage --> Enqueue{Static enabled?}
    Enqueue -->|no| Detonate
    Enqueue -->|yes| Static[static_analyze_sample<br/>Linux pool]
    Static --> Trigrams[Compute byte + opcode MinHash]
    Trigrams --> Similar[LSH similarity lookup]
    Similar -->|≥ threshold| ShortCircuit[Mark near-duplicate<br/>link lineage]
    Similar -->|< threshold| Detonate[analyze_malware_sample<br/>Windows pool]
    ShortCircuit --> Done
    Detonate --> Parse[Parse ProcMon + RegShot + PCAP]
    Parse --> STIX[Build STIX 2.1 bundle]
    STIX --> Persist[(Persist to Postgres)]
    Persist --> Quarantine[Move dropped files to quarantine]
    Quarantine --> Evasion[Detect anti-VM behaviour<br/>evasion_detector.py]
    Evasion --> Done([status=completed<br/>evasion_observed set])

    Done -.GET /analyses/id/bundle.-> GNATConsumer((GNAT connector))
```

## Component model

```mermaid
flowchart LR
    subgraph Host["Orchestrator host"]
        IntakeAPI["intake_api.py<br/>Flask: POST /submit, GET /jobs/id"]
        ExportAPI["export_api.py<br/>Flask blueprint: GET /analyses/*"]
        Intake["intake.py<br/>validate -> hash -> dedupe -> VT -> YARA"]
        TasksStatic["tasks_static.py<br/>Celery static_analyze_sample"]
        TasksDetonation["tasks.py<br/>Celery analyze_malware_sample"]
        GuestDriver["guest_driver.py<br/>submit_job / wait_for_result"]
        VmPool["vm_pool.py<br/>DB-backed lease"]
        Analyzer["analyzer.py<br/>artifacts -> STIX"]
        StaticAnalysis["static_analysis.py<br/>envelope -> bundle"]
        Similarity["similarity.py<br/>LSH lookup + decision"]
        Persistence["persistence.py<br/>all SQL lives here"]
        StixBuilder["stix_builder.py<br/>factories + UUIDv5 IDs"]
    end

    subgraph Shared["Shared wire schema (stdlib only)"]
        Schema["schema.py<br/>JobManifest / ResultEnvelope"]
        Trigrams["trigrams.py<br/>byte/opcode trigrams + MinHash"]
    end

    subgraph WinGuest["Windows guest (PyInstaller)"]
        WinWatcher["watcher.py"]
        WinRunner["runner.py"]
        WinCapture["capture/procmon, tshark, regshot, dropped"]
    end

    subgraph LinGuest["Linux static-analysis guest"]
        LinWatcher["watcher.py"]
        LinRunner["runner.py"]
        LinTools["tools/pe_elf, fuzzy, strings_entropy,<br/>yara_deep, capa, disasm_trigrams"]
    end

    IntakeAPI --> Intake
    IntakeAPI --> ExportAPI
    Intake --> Persistence
    Intake --> TasksStatic
    Intake --> TasksDetonation
    TasksStatic --> GuestDriver
    TasksStatic --> VmPool
    TasksStatic --> StaticAnalysis
    TasksStatic --> Similarity
    TasksStatic --> Persistence
    TasksDetonation --> GuestDriver
    TasksDetonation --> VmPool
    TasksDetonation --> Analyzer
    TasksDetonation --> Persistence
    Analyzer --> StixBuilder
    StaticAnalysis --> Trigrams
    Similarity --> Persistence

    GuestDriver -->|JobManifest| Schema
    WinWatcher --> Schema
    LinWatcher --> Schema
    LinTools --> Trigrams

    ExportAPI --> Persistence
```

## Happy-path sequence (detonation)

```mermaid
sequenceDiagram
    participant U as User / Upstream
    participant API as intake_api
    participant PG as Postgres
    participant Q as Redis
    participant ST as static task
    participant DT as detonation task
    participant SMB as staging share
    participant LG as Linux guest
    participant WG as Windows guest

    U->>API: POST /submit (bytes)
    API->>API: validate, hash, dedupe, VT, YARA
    API->>PG: INSERT analysis_jobs (status=queued)
    API->>SMB: write samples/{id}/name
    API->>Q: enqueue static_analyze_sample
    API-->>U: 202 {analysis_id, priority, ...}

    Q->>ST: static_analyze_sample(id)
    ST->>PG: acquire linux vmid lease
    ST->>SMB: publish manifest (mode=static_analysis)
    LG->>SMB: claim job, read bytes
    LG->>LG: pefile, ssdeep, YARA, CAPA, trigrams
    LG->>SMB: write static_analysis.json + trigrams + result.json
    ST->>SMB: poll for result.json
    ST->>PG: persist static_analysis, sample_trigrams, bands
    ST->>PG: LSH candidate fetch + Jaccard
    alt Jaccard >= threshold
        ST->>PG: mark near_duplicate_of
        ST-->>Q: done, no detonation
    else Jaccard < threshold
        ST->>Q: enqueue analyze_malware_sample
    end

    Q->>DT: analyze_malware_sample(id)
    DT->>PG: acquire windows vmid lease
    DT->>SMB: publish manifest (mode=detonation)
    WG->>SMB: claim job
    WG->>WG: RegShot baseline, start ProcMon + tshark
    WG->>WG: execute sample with timeout
    WG->>WG: collect dropped files, RegShot diff
    WG->>SMB: write artifacts + result.json
    DT->>SMB: poll for result.json
    DT->>DT: parse + analyze -> STIX bundle
    DT->>PG: persist STIX + normalised rows
    DT->>PG: update analysis_jobs (status=completed)
    DT->>PG: release vmid lease
```

## Request-time dependencies

Submissions are synchronous up to the enqueue. Actually waiting for a
detonation is minutes of queued+VM-boot+timeout+capture-export, so the
client polls `GET /jobs/<id>` or `GET /analyses/<id>` until status
becomes `completed` or `failed`.

| Step           | Typical latency      | Blocking? |
|----------------|----------------------|-----------|
| POST /submit   | 50–500 ms            | yes       |
| Static stage   | 15–120 s             | no (async) |
| Windows VM boot + detonation | 3–10 min | no (async) |
| Artifact export to SMB | 5–30 s       | no (async) |
| STIX persist + quarantine    | 1–5 s    | no (async) |
| Bundle fetch   | 20–200 ms            | yes       |

## What lives where

| Concern                         | Module                              |
|---------------------------------|-------------------------------------|
| HTTP surface                    | `intake_api.py`, `export_api.py`    |
| Input validation + prioritisation | `intake.py`                       |
| VT + YARA pre-checks            | `vt_client.py`, `yara_scanner.py`   |
| Celery tasks                    | `tasks.py`, `tasks_static.py`       |
| VM pool                         | `vm_pool.py`                        |
| Proxmox API calls               | `proxmox_client.py`                 |
| Host ↔ guest filesystem protocol | `guest_driver.py`                  |
| Wire schema (shared)            | `schema.py`                         |
| Artifact parsers (pure)         | `parsers/*.py`, `static_analysis.py` |
| STIX factories                  | `stix_builder.py`                   |
| Similarity engine               | `similarity.py`, `trigrams.py`      |
| Anti-analysis mitigations       | `guest_agent/activity/`, `guest_agent/stealth/` |
| Evasion detection (post-run)    | `evasion_detector.py`               |
| All SQL                         | `persistence.py`                    |

This split matters: parsers and STIX factories are **pure** (no DB, no
network) so they're trivially unit-testable; Celery tasks glue pure
code to the real world.
