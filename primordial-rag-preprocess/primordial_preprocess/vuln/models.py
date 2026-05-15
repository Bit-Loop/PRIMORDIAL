from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


ALLOWED_OUTPUT_MODES = [
    "vuln_triage",
    "affected_asset_mapping",
    "patch_prioritization",
    "exploitability_context",
    "defensive_detection_context",
    "report_context",
    "methodology_hint",
    "cve_compare",
    "cve_search_debug",
]

BLOCKED_OUTPUT_MODES = [
    "exploit_execution",
    "payload_generation",
    "real_target_attack_instructions",
    "automated_scanning",
    "action_selection",
    "scope_expansion",
    "persistence",
    "evasion",
    "credential_theft",
    "malware_behavior",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class CvssMetric(BaseModel):
    version: str = ""
    vector: str = ""
    base_score: float | None = None
    severity: str = ""
    source: str = ""


class ReferenceRecord(BaseModel):
    url: str
    source: str = ""
    tags: list[str] = Field(default_factory=list)


class AffectedPackage(BaseModel):
    ecosystem: str = ""
    name: str = ""
    purl: str = ""
    affected_versions: list[str] = Field(default_factory=list)
    ranges: list[dict[str, Any]] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)


class EpssSignal(BaseModel):
    probability: float | None = None
    percentile: float | None = None
    score_date: str = ""


class VulnSourceCursor(BaseModel):
    source_name: str
    cursor_type: str
    cursor_value: str = ""
    last_success_at: str | None = None
    last_attempt_at: str | None = None
    status: str = "pending"
    etag: str | None = None
    last_seen_commit: str | None = None
    last_seen_timestamp: str | None = None
    failure_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class VulnEvent(BaseModel):
    event_id: str
    source_name: str
    event_type: str
    source_record_id: str
    vuln_ids: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    occurred_at: str | None = None
    observed_at: str = Field(default_factory=utc_now_iso)
    raw_ref: str = ""
    payload_hash: str
    payload: dict[str, Any] = Field(default_factory=dict)
    status: str = "pending"
    error: str | None = None


class VulnerabilityRecord(BaseModel):
    vuln_id: str
    cve_id: str | None = None
    aliases: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    source_priority: int = Field(default=3, ge=1, le=5)
    title: str = ""
    description: str = ""
    published_at: str | None = None
    modified_at: str | None = None
    withdrawn_at: str | None = None
    rejected: bool = False
    affected_vendors: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    affected_packages: list[AffectedPackage] = Field(default_factory=list)
    affected_cpes: list[str] = Field(default_factory=list)
    affected_purls: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    cvss: list[CvssMetric] = Field(default_factory=list)
    kev: dict[str, Any] = Field(default_factory=dict)
    epss: EpssSignal | None = None
    references: list[ReferenceRecord] = Field(default_factory=list)
    exploit_references: list[ReferenceRecord] = Field(default_factory=list)
    patch_references: list[ReferenceRecord] = Field(default_factory=list)
    advisory_references: list[ReferenceRecord] = Field(default_factory=list)
    risk_tags: list[str] = Field(default_factory=list)
    methodology_tags: list[str] = Field(default_factory=list)
    raw_by_source: dict[str, Any] = Field(default_factory=dict)
    provenance: list[dict[str, Any]] = Field(default_factory=list)
    conflicts: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    safety_level: Literal["safe_planning", "passive_recon", "active_testing", "exploit_validation", "unknown"] = "safe_planning"
    allowed_output_modes: list[str] = Field(default_factory=lambda: list(ALLOWED_OUTPUT_MODES))
    blocked_output_modes: list[str] = Field(default_factory=lambda: list(BLOCKED_OUTPUT_MODES))


class AdvisoryDocRecord(BaseModel):
    advisory_doc_id: str
    source_file: str = ""
    source_url: str = ""
    source_sha256: str = ""
    source_type: str = ""
    publisher: str = ""
    title: str = ""
    published_at: str | None = None
    updated_at: str | None = None
    docling_json_path: str = ""
    markdown_path: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    ghsa_ids: list[str] = Field(default_factory=list)
    osv_ids: list[str] = Field(default_factory=list)
    extracted_facts_path: str = ""
    chunk_count: int = 0
    confidence: float = Field(default=0.65, ge=0.0, le=1.0)
    warnings: list[str] = Field(default_factory=list)


class AdvisoryExtractedFacts(BaseModel):
    advisory_title: str = ""
    publisher: str = ""
    published_at: str | None = None
    updated_at: str | None = None
    cve_ids: list[str] = Field(default_factory=list)
    ghsa_ids: list[str] = Field(default_factory=list)
    osv_ids: list[str] = Field(default_factory=list)
    affected_vendors: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    severity_text: str = ""
    cvss_vectors: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    exploit_status_claims: list[str] = Field(default_factory=list)
    workaround_steps: list[str] = Field(default_factory=list)
    remediation_steps: list[str] = Field(default_factory=list)
    mitigation_steps: list[str] = Field(default_factory=list)
    detection_notes: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    confidence_notes: list[str] = Field(default_factory=list)


class VulnerabilityIntelCard(BaseModel):
    card_id: str
    vuln_id: str
    cve_id: str | None = None
    aliases: list[str] = Field(default_factory=list)
    card_type: Literal[
        "vuln_summary",
        "affected_asset_mapping",
        "severity_context",
        "exploitability_signal",
        "remediation",
        "detection_context",
        "report_context",
        "methodology_hint",
        "reference_index",
    ]
    title: str
    retrieval_text: str
    domains: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    affected_packages: list[AffectedPackage] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    cvss: list[CvssMetric] = Field(default_factory=list)
    kev: dict[str, Any] = Field(default_factory=dict)
    epss: EpssSignal | None = None
    source_refs: list[ReferenceRecord] = Field(default_factory=list)
    confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    safety_notes: list[str] = Field(default_factory=list)
    allowed_output_modes: list[str] = Field(default_factory=lambda: list(ALLOWED_OUTPUT_MODES))
    blocked_output_modes: list[str] = Field(default_factory=lambda: list(BLOCKED_OUTPUT_MODES))
    source_priority: int = Field(default=3, ge=1, le=5)
    content_hash: str
    embedding_policy: str = "embed_if_relevant"
    active: bool = True
    supersedes: str | None = None
    modified_at: str = Field(default_factory=utc_now_iso)
