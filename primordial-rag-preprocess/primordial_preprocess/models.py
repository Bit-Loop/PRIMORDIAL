from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

DomainName = Literal[
    "api_web",
    "kubernetes_cloud",
    "systems_exploitation",
    "methodology_standards",
    "mitre_attack",
    "formal_methods",
    "general_security",
]

Difficulty = Literal["beginner", "intermediate", "advanced", "expert", "unknown"]

ALLOWED_USE_MODES = [
    "authorized_bug_bounty",
    "ctf",
    "local_lab",
    "defensive_assessment",
    "academic_study",
]


class SecurityDocProfile(BaseModel):
    title: str | None = None
    author_or_org: str | None = None
    year: int | None = None
    primary_domain: DomainName
    secondary_domains: list[str] = Field(default_factory=list)
    main_topics: list[str] = Field(default_factory=list)
    security_frameworks: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    difficulty: Difficulty = "unknown"
    best_use_modes: list[str] = Field(default_factory=lambda: list(ALLOWED_USE_MODES))
    requires_authorized_scope: bool = True
    summary: str = ""
    retrieval_priority: int = Field(default=3, ge=1, le=5)


class ChunkRecord(BaseModel):
    chunk_id: str
    doc_id: str
    source_file: str
    source_sha256: str
    source_type: str
    domain: DomainName
    secondary_domains: list[str] = Field(default_factory=list)
    title: str | None = None
    section: str | None = None
    page_start: int | None = None
    page_end: int | None = None
    chunk_index: int
    chunk_type: str
    retrieval_text: str
    raw_text: str
    requires_authorized_scope: bool = True
    allowed_use_modes: list[str] = Field(default_factory=lambda: list(ALLOWED_USE_MODES))
    metadata: dict[str, Any] = Field(default_factory=dict)


class MitreRecord(BaseModel):
    record_id: str
    matrix: Literal["enterprise", "ics", "mobile"]
    object_type: str
    attack_id: str | None = None
    name: str
    description: str
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    detections: list[str] = Field(default_factory=list)
    revoked: bool = False
    deprecated: bool = False
    external_references: list[dict[str, Any]] = Field(default_factory=list)


def domains_from_corpus_types(corpus_types: list[str], fallback: DomainName = "general_security") -> tuple[DomainName, list[str]]:
    ordered: list[DomainName] = []
    values = set(corpus_types)
    if {"api_security", "web_security"} & values:
        ordered.append("api_web")
    if {"kubernetes_security", "cloud_native_security", "container_security"} & values:
        ordered.append("kubernetes_cloud")
    if {"kernel_security", "binary_analysis", "hardware_security", "tool_usage"} & values:
        ordered.append("systems_exploitation")
    if {"engagement_governance"} & values:
        ordered.append("methodology_standards")
    if {"attack_taxonomy"} & values:
        ordered.append("mitre_attack")
    if {"formal_methods", "decision_procedures", "string_analysis", "protocol_verification", "model_checking", "program_analysis"} & values:
        ordered.append("formal_methods")
    if not ordered:
        ordered.append(fallback)
    primary = ordered[0]
    secondary = [item for item in ordered[1:] if item != primary]
    return primary, secondary
