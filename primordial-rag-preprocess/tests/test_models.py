from __future__ import annotations

from primordial_preprocess.models import ALLOWED_USE_MODES, ChunkRecord, SecurityDocProfile


def test_security_doc_profile_validates_priority_and_domain():
    profile = SecurityDocProfile(
        title="OWASP API Security",
        primary_domain="api_web",
        summary="API security profile.",
        retrieval_priority=5,
    )

    assert profile.requires_authorized_scope is True
    assert profile.best_use_modes == ALLOWED_USE_MODES


def test_chunk_record_requires_provenance_and_safety_metadata():
    record = ChunkRecord(
        chunk_id="chunk_1",
        doc_id="doc_1",
        source_file="source.md",
        source_sha256="abc",
        source_type="markdown",
        domain="api_web",
        chunk_index=0,
        chunk_type="docling_hybrid",
        retrieval_text="Heading\nBody",
        raw_text="Body",
    )

    assert record.requires_authorized_scope is True
    assert "ctf" in record.allowed_use_modes
