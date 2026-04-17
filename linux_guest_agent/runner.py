"""Per-job static-analysis pipeline.

Mirror of `guest_agent/runner.py` for the Linux static stage. Reads the
sample bytes once, fans them out to each tool, writes the consolidated
envelope + the two trigram blobs, returns a `ResultEnvelope`. No
detonation, no dynamic capture — just inspection of the bytes on disk.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orchestrator.schema import (
    MODE_STATIC_ANALYSIS,
    SCHEMA_VERSION,
    STATIC_ANALYSIS_JSON,
    TRIGRAMS_BYTE_BIN,
    TRIGRAMS_OPCODE_BIN,
    JobManifest,
    ResultEnvelope,
)

from .config import LinuxGuestConfig
from .tools import (
    analyze_pe_elf,
    compute_fuzzy_hashes,
    compute_trigram_signatures,
    extract_strings_and_entropy,
    run_capa,
    scan_deep_yara,
)


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def run_static_job(
    manifest: JobManifest, config: LinuxGuestConfig, workspace: Path
) -> ResultEnvelope:
    workspace.mkdir(parents=True, exist_ok=True)
    started_at = _iso_now()
    errors: list[str] = []

    sample_path = Path(manifest.sample_guest_path)
    if not sample_path.exists():
        return _failure_envelope(manifest, started_at, [f"sample missing at {sample_path}"])

    try:
        data = sample_path.read_bytes()
    except OSError as exc:
        return _failure_envelope(manifest, started_at, [f"read failed: {exc}"])

    envelope_payload: dict[str, Any] = {}
    opts = manifest.static

    if opts.pe_elf:
        envelope_payload["pe_elf"] = analyze_pe_elf(sample_path, data)
    if opts.fuzzy_hashes:
        envelope_payload["fuzzy"] = compute_fuzzy_hashes(data)
    if opts.strings_entropy:
        envelope_payload["strings_summary"] = extract_strings_and_entropy(
            data, max_strings_bytes=opts.max_strings_bytes
        )
    if opts.yara_deep:
        yara_result = scan_deep_yara(data, config.yara_deep_rules_dir)
        envelope_payload["yara_matches"] = [
            m["rule"] for m in yara_result.get("matches", [])
        ]
        envelope_payload["yara_detail"] = yara_result
    if opts.capa:
        capa_result = run_capa(
            sample_path, capa_exe=config.capa_exe, timeout_seconds=opts.per_tool_timeout_seconds
        )
        envelope_payload["capa_capabilities"] = capa_result.get("capabilities", [])
        envelope_payload["capa_detail"] = capa_result

    pe_elf = envelope_payload.get("pe_elf") or {}
    sections = pe_elf.get("sections")
    arch = pe_elf.get("architecture")

    if opts.trigrams_byte or opts.trigrams_opcode:
        trigrams_meta = compute_trigram_signatures(
            data=data,
            sections=sections,
            arch=arch,
            workspace=workspace,
            byte_filename=TRIGRAMS_BYTE_BIN,
            opcode_filename=TRIGRAMS_OPCODE_BIN,
        )
        envelope_payload["trigrams"] = trigrams_meta

    # Persist the consolidated envelope alongside the binary trigram blobs.
    envelope_payload["sample_sha256"] = manifest.sample_sha256
    envelope_payload["job_id"] = manifest.job_id
    (workspace / STATIC_ANALYSIS_JSON).write_text(
        json.dumps(envelope_payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    summary = _build_summary(envelope_payload)
    return ResultEnvelope(
        schema_version=SCHEMA_VERSION,
        job_id=manifest.job_id,
        status="completed",
        started_at=started_at,
        completed_at=_iso_now(),
        execution_duration_seconds=0.0,
        sample_pid=None,
        sample_exit_code=None,
        timed_out=False,
        mode=MODE_STATIC_ANALYSIS,
        captures=[],
        dropped_files=[],
        errors=errors,
        static_summary=summary,
    )


def _build_summary(payload: dict[str, Any]) -> dict[str, Any]:
    """Compact subset of the full envelope; flows through ResultEnvelope.static_summary
    so the host can make decisions without re-reading the larger JSON file."""
    pe_elf = payload.get("pe_elf") or {}
    fuzzy = payload.get("fuzzy") or {}
    return {
        "file_format": pe_elf.get("file_format"),
        "architecture": pe_elf.get("architecture"),
        "imphash": pe_elf.get("imphash"),
        "ssdeep": fuzzy.get("ssdeep"),
        "tlsh": fuzzy.get("tlsh"),
        "is_packed_heuristic": pe_elf.get("is_packed_heuristic"),
        "yara_match_count": len(payload.get("yara_matches") or []),
        "capa_capability_count": len(payload.get("capa_capabilities") or []),
    }


def _failure_envelope(
    manifest: JobManifest, started_at: str, errors: list[str]
) -> ResultEnvelope:
    return ResultEnvelope(
        schema_version=SCHEMA_VERSION,
        job_id=manifest.job_id,
        status="failed",
        started_at=started_at,
        completed_at=_iso_now(),
        execution_duration_seconds=0.0,
        sample_pid=None,
        sample_exit_code=None,
        timed_out=False,
        mode=MODE_STATIC_ANALYSIS,
        errors=errors,
    )
