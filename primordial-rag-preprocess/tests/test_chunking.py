from __future__ import annotations

import json

from primordial_preprocess.chunking import build_chunks
from primordial_preprocess.config import CorpusPolicy, ChunkPolicy


def _write_jsonl(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def test_chunk_ids_are_deterministic(tmp_path):
    source = {
        "source_id": "source_1",
        "sha256": "abc",
        "relative_path": "doc.md",
        "filename": "doc.md",
        "detected_type": "markdown",
        "authority_level": "official_standard",
        "corpus_type": ["web_security"],
        "domain": [],
        "risk_level": "safe_planning",
        "planner_visibility": "normal",
        "scope_gate_required": False,
        "requires_operator_approval": False,
        "license_status": "open_public",
        "policy_blocked": False,
    }
    extracted = {
        "source_id": "source_1",
        "source_sha256": "abc",
        "extracted": True,
        "backend": "docling",
        "policy_blocked": False,
        "warnings": [],
        "units": [{"text": "# Section\n\n" + ("alpha " * 200), "metadata": {"page": 3}}],
    }
    _write_jsonl(tmp_path / "classified_sources.jsonl", [source])
    _write_jsonl(tmp_path / "extracted_sources.jsonl", [extracted])
    policy = CorpusPolicy(chunking=ChunkPolicy(target_chars=300, overlap_chars=50))

    first = build_chunks(tmp_path, policy)
    second = build_chunks(tmp_path, policy)

    assert [chunk["chunk_id"] for chunk in first] == [chunk["chunk_id"] for chunk in second]
    assert first[0]["section_path"] == ["Section"]
    assert first[0]["page_start"] == 3


def test_policy_blocked_source_produces_no_chunks(tmp_path):
    source = {
        "source_id": "blocked",
        "sha256": "abc",
        "relative_path": "blocked.pdf",
        "filename": "blocked.pdf",
        "detected_type": "pdf",
        "authority_level": "explanatory_practical",
        "corpus_type": ["web_security"],
        "domain": [],
        "risk_level": "safe_planning",
        "planner_visibility": "normal",
        "scope_gate_required": False,
        "requires_operator_approval": False,
        "license_status": "unknown_commercial_or_proprietary",
        "policy_blocked": True,
    }
    extracted = {
        "source_id": "blocked",
        "source_sha256": "abc",
        "extracted": False,
        "backend": "docling",
        "policy_blocked": True,
        "units": [{"text": "should not emit", "metadata": {}}],
    }
    _write_jsonl(tmp_path / "classified_sources.jsonl", [source])
    _write_jsonl(tmp_path / "extracted_sources.jsonl", [extracted])

    assert build_chunks(tmp_path, CorpusPolicy()) == []
