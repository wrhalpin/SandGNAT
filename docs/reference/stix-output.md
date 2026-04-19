# STIX output reference

Every behavioural finding SandGNAT persists is a STIX 2.1 object. This
page documents the shape of each type we emit, the `x_`-prefixed
extensions we add, and the ID-derivation rule.

Source: `orchestrator/stix_builder.py`.

## ID derivation

Every SandGNAT-emitted STIX ID is a deterministic UUIDv5:

```python
SANDGNAT_NS = UUID("4f6e7d1c-3e8b-5b6e-9a23-7a1b6c2d8e4f")

def stix_id(stix_type, analysis_id, natural_key) -> str:
    raw = f"{analysis_id}|{stix_type}|{natural_key}"
    return f"{stix_type}--{uuid5(SANDGNAT_NS, raw)}"
```

This is what makes re-ingest idempotent: feeding the same
`completed/{analysis_id}/` workspace through the analyzer twice
produces identical STIX IDs, and `ON CONFLICT DO NOTHING` on the
persistence side makes the second pass a no-op.

**Do not change `SANDGNAT_NS`.** Changing it breaks idempotency
retroactively for the entire corpus.

## x_analysis_metadata

Required extension on **every** STIX object we emit. Links the object
back to an analysis job so the full bundle is recoverable by
`analysis_id`.

```json
{
  "x_analysis_metadata": {
    "analysis_id": "e3f1b4a2-...",
    "analysis_timestamp": "2026-04-17T12:00:00.000000Z",
    "tools_used": ["procmon", "regshot", "tshark"],
    "network_isolation": true,
    "sample_hash_sha256": "abc...",
    "vm_uuid": "...",
    "analyst_confidence_level": 85,
    "execution_duration_seconds": 300,
    "notes": "..."
  }
}
```

`sample_hash_sha256`, `vm_uuid`, `analyst_confidence_level`, `notes`,
`execution_duration_seconds` are optional.

## Malware SDO

One per analysis. Wraps every other object in the bundle via
`object_refs`.

```json
{
  "type": "malware",
  "spec_version": "2.1",
  "id": "malware--<uuid5>",
  "created": "2026-04-17T12:00:00.000000Z",
  "modified": "2026-04-17T12:00:00.000000Z",
  "name": "sample.exe",
  "description": "Runtime analysis: status=completed",
  "malware_types": ["unknown"],
  "is_family": false,
  "labels": ["malware"],
  "object_refs": [
    "file--...",
    "process--...",
    "network-traffic--...",
    "indicator--..."
  ],
  "x_analysis_metadata": {...}
}
```

`malware_types` defaults to `["unknown"]`. Callers may set a richer
set from a vocab (`trojan`, `worm`, `rat`, `ransomware`, ...).

Natural key: `sample_hash_sha256`.

## File SCO

One for the sample itself, one per dropped file.

```json
{
  "type": "file",
  "spec_version": "2.1",
  "id": "file--<uuid5>",
  "hashes": {
    "SHA-256": "abc...",
    "MD5": "xyz...",
    "SHA-1": "qwe...",
    "SSDEEP": "96:abc:def",
    "TLSH": "T1ABCDE...",
    "x_imphash": "deadbeef..."
  },
  "name": "evil.exe",
  "size": 4096,
  "mime_type": "application/x-msdownload",
  "x_analysis_metadata": {...},
  "x_created_by_process_ref": "process--...",
  "x_quarantine_path": "/srv/sandgnat/quarantine/.../payload.dll",
  "x_artifact_disposition": "quarantined"
}
```

Standard keys under `hashes`: `SHA-256`, `MD5`, `SHA-1`, `SSDEEP`,
`TLSH`. The `x_imphash` key is an extension because imphash isn't in
STIX's `hash-algorithm-ov`.

`x_created_by_process_ref` points at the `process` observable that
wrote the file. `x_quarantine_path` and `x_artifact_disposition` are
present on dropped files after quarantine ingestion.

Natural key: `sha256`.

## Process SCO

One per distinct PID observed in ProcMon.

```json
{
  "type": "process",
  "spec_version": "2.1",
  "id": "process--<uuid5>",
  "pid": 1234,
  "name": "sample.exe",
  "created_time": "2026-04-17T12:00:00.000000Z",
  "binary_ref": "file--...",            // if name ends .exe
  "parent_ref": "process--...",          // when known
  "child_process_refs": ["process--..."],
  "x_registry_modifications": [
    {
      "action": "set_value",
      "key": "HKLM\\...\\Run",
      "value_detail": "Type: REG_SZ, Length: ..."
    }
  ],
  "x_analysis_metadata": {...}
}
```

`x_registry_modifications` is a per-process summary of RegSetValue
events — a convenience for consumers who want a quick "what did this
process change?" view without joining against `registry_modifications`.

Natural key: `pid + name`.

## Network-traffic SCO

One per distinct flow in the PCAP.

```json
{
  "type": "network-traffic",
  "spec_version": "2.1",
  "id": "network-traffic--<uuid5>",
  "src_ref": "ipv4-addr--<uuid5>",
  "dst_ref": "ipv4-addr--<uuid5>",
  "protocols": ["tcp"],
  "src_port": 49152,
  "dst_port": 443,
  "start": "2026-04-17T12:00:12.000000Z",
  "end": "2026-04-17T12:00:12.500000Z",
  "x_http_headers": {"Host": "c2.example", "User-Agent": "..."},
  "x_analysis_metadata": {...}
}
```

`src_ref`/`dst_ref` point at `ipv4-addr` (or `ipv6-addr`, or
`domain-name`) SCOs emitted alongside.

`x_http_headers` only present when the PCAP parser recovers them.

Natural key: `src_ip:src_port -> dst_ip:dst_port + protocol`.

## Indicator SDO

Emitted for each persistence-flagged registry modification and each
confirmed network IOC.

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--<uuid5>",
  "created": "...",
  "modified": "...",
  "pattern": "[windows-registry-key:key = 'HKLM\\Software\\...']",
  "pattern_type": "stix",
  "pattern_version": "2.1",
  "valid_from": "...",
  "labels": ["malicious-activity", "persistence"],
  "kill_chain_phases": [
    {"kill_chain_name": "mitre-attack", "phase_name": "persistence"}
  ],
  "x_observable_refs": ["windows-registry-key--..."],
  "x_analysis_metadata": {...}
}
```

Two pattern classes we emit:

- Registry-persistence: matches a specific run-key.
- Network IOC: matches a `network-traffic:dst_ref.value` or
  `domain-name:value`.

`x_observable_refs` links the indicator to the SCOs it matches,
making the graph explicit without requiring full STIX `relationship`
SDOs.

## ipv4-addr / ipv6-addr / domain-name SCOs

Compact observables, emitted alongside `network-traffic` when the
PCAP parser sees them.

```json
{
  "type": "ipv4-addr",
  "spec_version": "2.1",
  "id": "ipv4-addr--<uuid5>",
  "value": "203.0.113.42",
  "x_analysis_metadata": {...}
}
```

Natural key: the address value.

## directory SCO

Rare but possible: emitted when dropped-file paths include a previously
unseen intermediate directory. Natural key: the path as a string.

## Bundle assembly

`persistence.export_bundle(analysis_id)` SELECTs every STIX row for the
analysis and hands them to `stix_builder.build_bundle`:

```json
{
  "type": "bundle",
  "id": "bundle--<uuid>",
  "spec_version": "2.1",
  "objects": [ ... every SDO + SCO + indicator for the analysis_id ... ]
}
```

The bundle's `id` is derived from its contents so two identical
bundles share an id.

## Things we deliberately don't emit

- **`relationship` SDOs** — `object_refs` on `malware` + `x_*_refs`
  on children cover the graph we need. Explicit relationship SDOs add
  ceremony without new signal.
- **`attack-pattern` SDOs from CAPA capabilities** — CAPA output lives
  in the normalised `static_analysis.capa_capabilities` JSONB column.
  Lifting it to STIX SDOs is a future enhancement.
- **`campaign`, `intrusion-set`, `threat-actor`** — those are
  analyst-curated, not machine-observable.
- **Any object without `x_analysis_metadata.analysis_id`** — the
  persistence layer would reject it. Test `test_stix_builder.py`
  guards this.
