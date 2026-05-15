from __future__ import annotations

import json

import pytest

from primordial_preprocess.chunking import build_chunks
from primordial_preprocess.config import CorpusPolicy
from primordial_preprocess.extraction.docling import docling_available, extract_with_docling


@pytest.mark.skipif(not docling_available(), reason="Docling is not installed")
def test_docling_json_chunks_with_hybrid_chunker(tmp_path):
    source = tmp_path / "source.md"
    source.write_text("# API Security\n\n## BOLA\n\nCapture object identifiers and authorization evidence.", encoding="utf-8")
    docling_json = tmp_path / "converted" / "source.json"
    markdown = tmp_path / "converted" / "source.md"
    extract_with_docling(source, docling_json_path=docling_json, markdown_path=markdown)

    classified = {
        "source_id": "source_1",
        "sha256": "abc",
        "relative_path": "source.md",
        "filename": "source.md",
        "detected_type": "markdown",
        "authority_level": "official_standard",
        "corpus_type": ["api_security"],
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
        "docling_json_path": str(docling_json),
        "markdown_path": str(markdown),
        "warnings": [],
        "units": [],
    }
    (tmp_path / "classified_sources.jsonl").write_text(json.dumps(classified) + "\n", encoding="utf-8")
    (tmp_path / "extracted_sources.jsonl").write_text(json.dumps(extracted) + "\n", encoding="utf-8")

    chunks = build_chunks(tmp_path, CorpusPolicy())

    assert chunks
    assert chunks[0]["chunk_type"] == "docling_hybrid"
    assert chunks[0]["domain"] == "api_web"
    assert chunks[0]["retrieval_text"]
    assert chunks[0]["raw_text"]
