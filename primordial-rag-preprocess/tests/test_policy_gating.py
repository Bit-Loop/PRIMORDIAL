from __future__ import annotations

from pathlib import Path

from primordial_preprocess.config import CorpusPolicy, SourceOverride
from primordial_preprocess.extraction.runner import extract_sources
from primordial_preprocess.extraction.docling import DoclingExtractionUnavailable
from primordial_preprocess.policy import apply_policy_to_record


def test_unknown_commercial_book_is_policy_blocked():
    record = {
        "sha256": "abc",
        "recommended_keep": True,
        "planner_visibility": "normal",
        "detected_type": "pdf",
        "filename": "API Security in Action.pdf",
        "license_status": "unknown_commercial_or_proprietary",
    }
    result = apply_policy_to_record(record, CorpusPolicy())
    assert result["policy_blocked"] is True
    assert "commercial" in result["policy_block_reason"]


def test_operator_override_allows_licensed_source():
    record = {
        "sha256": "abc",
        "recommended_keep": True,
        "planner_visibility": "normal",
        "detected_type": "pdf",
        "filename": "API Security in Action.pdf",
        "license_status": "unknown_commercial_or_proprietary",
    }
    override = SourceOverride(sha256="abc", license_status="licensed_for_private_rag", extraction_allowed=True)
    result = apply_policy_to_record(record, CorpusPolicy(), override)
    assert result["policy_blocked"] is False
    assert result["license_status"] == "licensed_for_private_rag"


def test_no_fallback_when_docling_unavailable(monkeypatch, tmp_path):
    source = tmp_path / "allowed.md"
    source.write_text("# Title\n\nBody", encoding="utf-8")
    record = {
        "source_id": "source_1",
        "sha256": "abc",
        "relative_path": "allowed.md",
        "original_path": str(source),
        "detected_type": "markdown",
        "filename": "allowed.md",
        "authority_level": "official_standard",
        "corpus_type": ["web_security"],
        "planner_visibility": "normal",
        "risk_level": "safe_planning",
        "scope_gate_required": False,
        "requires_operator_approval": False,
        "license_status": "open_public",
        "policy_blocked": False,
    }

    def fail_docling(path: Path, *, allow_ocr: bool = False, **kwargs):
        raise DoclingExtractionUnavailable("forced missing docling")

    monkeypatch.setattr("primordial_preprocess.extraction.runner.extract_with_docling", fail_docling)
    results = extract_sources([record], tmp_path / "out", CorpusPolicy())

    assert results[0]["extracted"] is False
    assert results[0]["backend"] == "docling"
    assert "forced missing docling" in results[0]["extraction_error"]
