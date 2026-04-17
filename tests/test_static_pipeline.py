"""Branch-coverage test for `tasks_static.static_analyze_sample`.

We don't run the actual Celery task (that requires a broker + Postgres +
Proxmox); instead we exercise the deciding helper `_persist_and_find_similar`
plus the `enqueue_analysis` routing, which together encode the two branches
the task picks between (chain vs short-circuit).
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from uuid import uuid4

from orchestrator.similarity import (
    InMemorySimilarityStore,
    cache_top_edges,
    find_similar,
    short_circuit_decision,
)
from orchestrator.static_analysis import StaticAnalysisBundle
from orchestrator.models import StaticAnalysisRow
from orchestrator.trigrams import minhash_bytes


def _settings(threshold: float = 0.85, flavour: str = "either"):  # type: ignore[no-untyped-def]
    return SimpleNamespace(
        static=SimpleNamespace(
            short_circuit_threshold=threshold,
            short_circuit_flavour=flavour,
        )
    )


def _bundle_with_signatures(byte_sig=None, opcode_sig=None):  # type: ignore[no-untyped-def]
    return StaticAnalysisBundle(
        row=StaticAnalysisRow(analysis_id=uuid4()),
        byte_signature=byte_sig,
        opcode_signature=opcode_sig,
    )


def test_persist_and_find_similar_returns_hit_when_above_threshold() -> None:
    from orchestrator.tasks_static import _persist_and_find_similar

    store = InMemorySimilarityStore()
    parent_id = uuid4()
    parent_sha = "a" * 64
    data = b"sandgnat-static-corpus-fixture" * 64
    parent_sig = minhash_bytes(data)
    store.store_signature(parent_id, parent_sha, "byte", parent_sig)

    new_id = uuid4()
    bundle = _bundle_with_signatures(byte_sig=minhash_bytes(data))

    hit = _persist_and_find_similar(
        new_id, "b" * 64, bundle, store, _settings(threshold=0.85)
    )
    assert hit is not None
    assert hit.analysis_id == parent_id
    assert hit.similarity >= 0.85
    assert hit.flavour == "byte"


def test_persist_and_find_similar_returns_none_for_unrelated_sample() -> None:
    from orchestrator.tasks_static import _persist_and_find_similar

    store = InMemorySimilarityStore()
    # Pre-load store with one unrelated sample.
    store.store_signature(
        uuid4(), "z" * 64, "byte", minhash_bytes(os.urandom(4096))
    )

    bundle = _bundle_with_signatures(byte_sig=minhash_bytes(os.urandom(4096)))
    hit = _persist_and_find_similar(
        uuid4(), "n" * 64, bundle, store, _settings(threshold=0.85)
    )
    assert hit is None


def test_persist_and_find_similar_respects_byte_flavour_preference() -> None:
    """When operator pins to 'byte', an opcode hit alone shouldn't trigger."""
    from orchestrator.tasks_static import _persist_and_find_similar

    store = InMemorySimilarityStore()
    parent_id = uuid4()
    opcode_sig = minhash_bytes(b"opcode-corpus" * 200)
    # Store only an opcode signature for the parent.
    store.store_signature(parent_id, "p" * 64, "opcode", opcode_sig)

    bundle = _bundle_with_signatures(opcode_sig=opcode_sig)
    hit = _persist_and_find_similar(
        uuid4(), "n" * 64, bundle, store, _settings(threshold=0.85, flavour="byte")
    )
    assert hit is None  # operator pinned to byte; opcode-only hit is ignored


def test_short_circuit_decision_picks_higher_score_under_either() -> None:
    """The 'either' preference picks the better-scoring flavour when both fire."""
    from orchestrator.tasks_static import _persist_and_find_similar

    store = InMemorySimilarityStore()
    parent_id = uuid4()
    same_data = b"corpus-bytes-XXXXXX" * 200

    # Both byte and opcode signatures stored for the parent.
    store.store_signature(parent_id, "p" * 64, "byte", minhash_bytes(same_data))
    store.store_signature(parent_id, "p" * 64, "opcode", minhash_bytes(same_data))

    bundle = _bundle_with_signatures(
        byte_sig=minhash_bytes(same_data),
        opcode_sig=minhash_bytes(same_data),
    )
    hit = _persist_and_find_similar(
        uuid4(), "n" * 64, bundle, store, _settings(threshold=0.85, flavour="either")
    )
    assert hit is not None
    assert hit.analysis_id == parent_id
    assert hit.similarity >= 0.85


def test_enqueue_analysis_routes_to_static_when_enabled(monkeypatch) -> None:
    """When STATIC_ANALYSIS_ENABLED is on, intake's enqueue path dispatches to
    the static task rather than directly to the detonation task."""
    from orchestrator import tasks as tasks_mod

    captured: dict[str, tuple] = {}

    class _Settings:
        class static:  # noqa: N801 — mimic dataclass attr access
            enabled = True

    monkeypatch.setattr(tasks_mod, "get_settings", lambda: _Settings())

    def fake_static_enqueuer(*args, **kwargs):  # noqa: ANN001
        captured["static"] = (args, kwargs)

    def fake_apply_async(*args, **kwargs):  # noqa: ANN001
        captured["detonation"] = (args, kwargs)

    monkeypatch.setattr(
        "orchestrator.tasks_static.enqueue_static_analysis", fake_static_enqueuer
    )
    monkeypatch.setattr(tasks_mod.analyze_malware_sample, "apply_async", fake_apply_async)

    job_id = uuid4()
    tasks_mod.enqueue_analysis(job_id, "x.exe", "sha", 60, 5)

    assert "static" in captured
    assert "detonation" not in captured


def test_enqueue_analysis_falls_back_to_detonation_when_disabled(monkeypatch) -> None:
    from orchestrator import tasks as tasks_mod

    captured: dict[str, tuple] = {}

    class _Settings:
        class static:  # noqa: N801
            enabled = False

    monkeypatch.setattr(tasks_mod, "get_settings", lambda: _Settings())

    def fake_apply_async(*args, **kwargs):  # noqa: ANN001
        captured["detonation"] = (args, kwargs)

    monkeypatch.setattr(tasks_mod.analyze_malware_sample, "apply_async", fake_apply_async)

    tasks_mod.enqueue_analysis(uuid4(), "x.exe", "sha", 60, 5)

    assert "detonation" in captured
