<p align="center">
  <img src="../assets/logo/sandgnat-logo-256.png" alt="SandGNAT" width="128">
</p>

# SandGNAT documentation

**Rendered site:** [wrhalpin.github.io/SandGNAT](https://wrhalpin.github.io/SandGNAT/)

Organised with the [Diátaxis](https://diataxis.fr/) framework: every
document sits in exactly one of four quadrants based on whether it's
oriented towards **learning** vs **working** and **action** vs **study**.

|                | **Action (doing)**              | **Study (reading)**            |
|----------------|---------------------------------|--------------------------------|
| **Learning**   | [Tutorials](tutorials/)         | [Explanation](explanation/)    |
| **Working**    | [How-to guides](how-to/)        | [Reference](reference/)        |

Start here if you're:

- **New**: [tutorials/01-your-first-sample.md](tutorials/01-your-first-sample.md)
- **Operating a live sandbox**: [how-to/](how-to/)
- **Looking up a specific thing**: [reference/](reference/)
- **Wondering "why does it work this way?"**: [explanation/](explanation/)

## Contents

### Tutorials (learn by doing)

Step-by-step, guaranteed-success walkthroughs for newcomers.

- [01 — Your first sample](tutorials/01-your-first-sample.md)
- [02 — Stand up a local dev stack](tutorials/02-local-dev-stack.md)
- [03 — Force a reanalysis and see a near-duplicate](tutorials/03-force-reanalysis.md)

### How-to guides (solve specific problems)

Task-focused recipes. Assumes you know roughly what you want to
accomplish.

- [Apply database migrations](how-to/apply-migrations.md)
- [Configure the VirusTotal pre-check](how-to/configure-virustotal.md)
- [Configure YARA rules (intake + deep)](how-to/configure-yara.md)
- [Add a new artifact parser](how-to/add-a-parser.md)
- [Build the Windows detonation guest](how-to/build-windows-guest.md)
- [Build the Linux static-analysis guest](how-to/build-linux-guest.md)
- [Run the intake service under gunicorn](how-to/run-under-gunicorn.md)
- [Tune the VM pools](how-to/tune-vm-pools.md)
- [Query the export API from a script](how-to/query-export-api.md)

### Reference (look up the details)

Complete, accurate, dry descriptions of the machinery. Nothing here tries
to teach.

- [Configuration (all env vars)](reference/configuration.md)
- [HTTP API](reference/http-api.md)
- [Database schema](reference/database-schema.md) — with ER diagram
- [Wire protocol (host ↔ guest)](reference/wire-protocol.md)
- [Celery tasks](reference/celery-tasks.md)
- [STIX output](reference/stix-output.md)

### Explanation (understand the "why")

Discursive discussion of design decisions, theory, and tradeoffs.

- [Architecture overview](explanation/architecture.md) — topology + pipeline diagrams
- [Why STIX 2.1 as the output format](explanation/why-stix.md)
- [Trigram similarity and LSH](explanation/similarity.md)
- [Near-duplicate short-circuit](explanation/near-duplicate-short-circuit.md)
- [Isolation and threat model](explanation/isolation-model.md)
- [GNAT integration: pull, not push](explanation/gnat-integration.md)

## Additional documents

- [`MALWARE_ANALYSIS_SYSTEM_DESIGN.md`](MALWARE_ANALYSIS_SYSTEM_DESIGN.md) —
  the canonical architecture + roadmap document. Referenced heavily from
  the explanation docs; read it before making architectural changes.
