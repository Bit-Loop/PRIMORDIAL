from __future__ import annotations

from primordial_preprocess.models import ALLOWED_USE_MODES, ChunkRecord, SecurityDocProfile
from primordial_preprocess.vuln.models import VulnEvent, VulnerabilityIntelCard, VulnerabilityRecord


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


def test_vulnerability_models_preserve_safety_defaults():
    record = VulnerabilityRecord(vuln_id="CVE-2026-0001", cve_id="CVE-2026-0001")
    event = VulnEvent(
        event_id="event_1",
        source_name="kev",
        event_type="kev.added",
        source_record_id="CVE-2026-0001",
        payload_hash="abc",
    )
    card = VulnerabilityIntelCard(
        card_id="vuln_card_1",
        vuln_id=record.vuln_id,
        cve_id=record.cve_id,
        card_type="vuln_summary",
        title="CVE-2026-0001 summary",
        retrieval_text="Vulnerability: CVE-2026-0001",
        content_hash="abc",
    )

    assert event.event_type == "kev.added"
    assert "action_selection" in record.blocked_output_modes
    assert "exploit_execution" in card.blocked_output_modes
