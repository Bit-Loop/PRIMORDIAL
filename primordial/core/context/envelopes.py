from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
from typing import Any

from primordial.core.context.normalization import (
    canonical_rag_domain,
    metadata_list_value,
    metadata_value,
    normalized_context_key,
    normalized_metadata_value,
)
from primordial.core.context.source_refs import is_source_refs_metadata_key
from primordial.core.context.source_types import RAG_ADVISORY_SOURCE_TYPES
from primordial.core.domain.models import utc_now


PLACEHOLDER_RAG_CITATION_SUFFIXES = frozenset({"none", "null", "unknown"})
CANONICAL_CITATION_PREFIXES = ("evidence:", "note:", "rag:")
RAG_CHUNK_FORMAT_SOURCE_TYPES = frozenset({"csv", "docling", "html", "json", "markdown", "md", "pdf", "text", "txt"})
RAG_CHUNK_VULN_INTEL_SOURCE_TYPES = frozenset({"vulnerability_intel_card", "vuln_intel_card"})
RAG_CHUNK_VULN_INTEL_DOMAINS = frozenset({"cve", "cve_advisory", "kev", "nvd", "vuln", "vuln_intel"})
RAG_CHUNK_WRITEUP_CORPORA = frozenset({"ctf_writeup", "htb_writeup", "walkthrough", "writeup"})


@dataclass(slots=True)
class ContextEnvelope:
    ref: str
    kind: str
    authority: str
    source_type: str
    purpose: str
    sink: str
    content: str
    target_id: str | None = None
    active_generation_id: str | None = None
    engagement_id: str | None = None
    scope_id: str | None = None
    corpus: str | None = None
    domain: str | None = None
    valid_for: list[str] = field(default_factory=list)
    invalid_for: list[str] = field(default_factory=list)
    citations: list[str] = field(default_factory=list)
    content_hash: str = ""
    created_at: str = field(default_factory=lambda: utc_now().isoformat())
    created_by: str = "primordial"
    review_status: str = "unreviewed"
    poison_flags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.ref = _canonical_citation_ref(self.ref)
        self.kind = normalized_context_key(self.kind)
        self.authority = normalized_context_key(self.authority)
        self.source_type = normalized_context_key(self.source_type)
        self.purpose = normalized_context_key(self.purpose)
        self.sink = normalized_context_key(self.sink)
        self.valid_for = _normalized_list(self.valid_for, lower=True, name="valid_for")
        self.invalid_for = _normalized_list(self.invalid_for, lower=True, name="invalid_for")
        self.poison_flags = _normalized_list(self.poison_flags, lower=True, name="poison_flags")
        self.citations = [_canonical_citation_ref(ref) for ref in _normalized_list(self.citations, name="citations")]
        if self.metadata is None:
            self.metadata = {}
        elif isinstance(self.metadata, Mapping):
            self.metadata = dict(self.metadata)
        else:
            raise ValueError("metadata must be a mapping")
        self.metadata = _canonical_metadata_refs(self.metadata)
        if not self.content_hash:
            self.content_hash = hashlib.sha256(str(self.content or "").encode("utf-8")).hexdigest()

    @classmethod
    def from_rag_chunk(
        cls,
        chunk: dict[str, Any],
        *,
        purpose: str,
        sink: str,
        target_id: str | None = None,
        active_generation_id: str | None = None,
    ) -> "ContextEnvelope":
        chunk_id = str(chunk.get("chunk_id") or chunk.get("id") or "").strip()
        raw_metadata = chunk.get("metadata")
        if raw_metadata is None:
            metadata: dict[str, Any] = {}
        elif isinstance(raw_metadata, Mapping):
            metadata = dict(raw_metadata)
        else:
            raise ValueError("metadata must be a mapping")
        envelope_metadata = _metadata_with_top_level_source_refs(chunk, metadata)
        citation = _rag_citation_id(chunk, metadata, chunk_id)
        text = str(
            metadata_value(chunk, "text")
            or metadata_value(chunk, "retrieval_text")
            or metadata_value(chunk, "excerpt")
            or metadata_value(chunk, "raw_text")
            or metadata_value(metadata, "text")
            or metadata_value(metadata, "retrieval_text")
            or metadata_value(metadata, "excerpt")
            or metadata_value(metadata, "raw_text")
            or ""
        )
        envelope_target_id = _explicit_or_payload_value(target_id, chunk, metadata, "target_id")
        envelope_generation_id = _explicit_or_payload_value(
            active_generation_id,
            chunk,
            metadata,
            "active_generation_id",
            "generation_id",
            "active_ip_generation",
        )
        return cls(
            ref=citation,
            kind="rag",
            authority="advisory",
            source_type=_rag_source_type(chunk, metadata),
            target_id=envelope_target_id,
            active_generation_id=envelope_generation_id,
            corpus=_rag_domain_field(metadata_value(metadata, "corpus_type") or metadata_value(chunk, "corpus_type")),
            domain=_rag_domain_field(metadata_value(metadata, "domain") or metadata_value(chunk, "domain")),
            purpose=purpose,
            sink=sink,
            valid_for=_list_field(chunk, metadata, "valid_for"),
            invalid_for=_list_field(chunk, metadata, "invalid_for"),
            citations=[citation] if citation else [],
            content=text,
            poison_flags=_list_field(chunk, metadata, "poison_flags"),
            metadata=envelope_metadata,
        )

    def as_payload(self) -> dict[str, Any]:
        return {
            "ref": self.ref,
            "kind": self.kind,
            "authority": self.authority,
            "source_type": self.source_type,
            "target_id": self.target_id,
            "active_generation_id": self.active_generation_id,
            "engagement_id": self.engagement_id,
            "scope_id": self.scope_id,
            "corpus": self.corpus,
            "domain": self.domain,
            "purpose": self.purpose,
            "sink": self.sink,
            "valid_for": list(self.valid_for),
            "invalid_for": list(self.invalid_for),
            "citations": list(self.citations),
            "content_hash": self.content_hash,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "review_status": self.review_status,
            "poison_flags": list(self.poison_flags),
            "metadata": dict(self.metadata),
            "content": self.content,
        }


def _rag_citation_id(chunk: dict[str, Any], metadata: dict[str, Any], chunk_id: str) -> str:
    for candidate in (
        metadata_value(chunk, "citation_id"),
        metadata_value(metadata, "citation_id"),
        chunk_id,
        "unknown",
    ):
        value = str(candidate or "").strip()
        if not value:
            continue
        if value.lower().startswith("rag:"):
            suffix = value[4:].strip()
            if suffix and suffix.lower() not in PLACEHOLDER_RAG_CITATION_SUFFIXES:
                return f"rag:{suffix}"
            continue
        if value.lower() in PLACEHOLDER_RAG_CITATION_SUFFIXES:
            continue
        return f"rag:{value}"
    return "rag:unknown"


def _canonical_citation_ref(value: object) -> str:
    ref = str(value or "").strip()
    for prefix in CANONICAL_CITATION_PREFIXES:
        if ref.lower().startswith(prefix):
            return f"{prefix}{ref[len(prefix):].strip()}"
    return ref


def _canonical_metadata_refs(metadata: dict[str, Any]) -> dict[str, Any]:
    normalized, source_refs, malformed_source_refs = _canonical_metadata_ref_node(metadata)
    if source_refs or malformed_source_refs is not None:
        normalized["source_refs"] = malformed_source_refs if malformed_source_refs is not None else list(dict.fromkeys(source_refs))
    return normalized


def _metadata_with_top_level_source_refs(chunk: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    envelope_metadata = dict(metadata)
    for key, value in chunk.items():
        if is_source_refs_metadata_key(key):
            if key in envelope_metadata:
                envelope_metadata[key] = _merge_source_refs_metadata_value(envelope_metadata[key], value)
            else:
                envelope_metadata[key] = value
    return envelope_metadata


def _merge_source_refs_metadata_value(existing: Any, incoming: Any) -> Any:
    existing_refs, existing_malformed = _source_refs_from_metadata_value(existing)
    incoming_refs, incoming_malformed = _source_refs_from_metadata_value(incoming)
    if existing_malformed is not None:
        return existing_malformed
    if incoming_malformed is not None:
        return incoming_malformed
    return [*existing_refs, *incoming_refs]


def _canonical_metadata_ref_node(value: Any) -> tuple[Any, list[str], Any]:
    if isinstance(value, Mapping):
        return _canonical_metadata_ref_mapping(value)
    if isinstance(value, (frozenset, list, set, tuple)):
        normalized_items: list[Any] = []
        source_refs: list[str] = []
        malformed_source_refs: Any = None
        for item in value:
            normalized_item, item_refs, item_malformed = _canonical_metadata_ref_node(item)
            normalized_items.append(normalized_item)
            source_refs.extend(item_refs)
            if item_malformed is not None:
                malformed_source_refs = item_malformed
        return normalized_items, source_refs, malformed_source_refs
    return value, [], None


def _canonical_metadata_ref_mapping(metadata: Mapping[str, Any]) -> tuple[dict[str, Any], list[str], Any]:
    normalized: dict[str, Any] = {}
    source_refs: list[str] = []
    malformed_source_refs: Any = None
    for key, value in metadata.items():
        if is_source_refs_metadata_key(key):
            item_refs, item_malformed = _source_refs_from_metadata_value(value)
            source_refs.extend(item_refs)
            if item_malformed is not None:
                malformed_source_refs = item_malformed
            continue
        normalized_value, item_refs, item_malformed = _canonical_metadata_ref_node(value)
        normalized[key] = normalized_value
        source_refs.extend(item_refs)
        if item_malformed is not None:
            malformed_source_refs = item_malformed
    return normalized, source_refs, malformed_source_refs


def _source_refs_from_metadata_value(value: Any) -> tuple[list[str], Any]:
    if isinstance(value, str):
        return [_canonical_citation_ref(value)], None
    if isinstance(value, (frozenset, list, set, tuple)):
        if any(not isinstance(ref, str) for ref in value):
            return [], value
        return [_canonical_citation_ref(ref) for ref in value], None
    return [], value


def _rag_domain_field(value: object) -> str:
    if not str(value or "").strip():
        return ""
    return canonical_rag_domain(value)


def _rag_source_type(chunk: dict[str, Any], metadata: dict[str, Any]) -> str:
    source_type = normalized_metadata_value(metadata, "source_type") or normalized_metadata_value(chunk, "source_type")
    if source_type in RAG_ADVISORY_SOURCE_TYPES or source_type in {"generated_export", "export_archive"}:
        return source_type
    if source_type in RAG_CHUNK_VULN_INTEL_SOURCE_TYPES:
        return "vuln_intel"
    if source_type in RAG_CHUNK_FORMAT_SOURCE_TYPES or not source_type:
        candidates = [
            normalized_metadata_value(metadata, "corpus_type"),
            normalized_metadata_value(chunk, "corpus_type"),
            normalized_metadata_value(metadata, "domain"),
            normalized_metadata_value(chunk, "domain"),
        ]
        if any(candidate in RAG_CHUNK_VULN_INTEL_DOMAINS for candidate in candidates):
            return "vuln_intel"
        if any(candidate in RAG_CHUNK_WRITEUP_CORPORA for candidate in candidates):
            return "writeup"
        return "methodology_doc"
    return source_type


def _normalized_list(values: Any, *, lower: bool = False, name: str = "context list") -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    elif isinstance(values, (frozenset, list, set, tuple)):
        values = list(values)
    else:
        raise ValueError(f"{name} must be a string or list-like value")
    normalized: list[str] = []
    for item in values:
        value = str(item).strip()
        if value:
            normalized.append(normalized_context_key(value) if lower else value)
    return normalized


def _list_field(chunk: dict[str, Any], metadata: dict[str, Any], name: str) -> list[str]:
    value = metadata_list_value(chunk, name)
    if not value:
        value = metadata_list_value(metadata, name)
    if not value:
        value = metadata_value(chunk, name)
    if value is None:
        value = metadata_value(metadata, name)
    return _normalized_list(value, name=name)


def _explicit_or_payload_value(
    explicit: str | None,
    chunk: dict[str, Any],
    metadata: dict[str, Any],
    *names: str,
) -> str | None:
    explicit_text = str(explicit).strip() if explicit is not None else ""
    if explicit_text:
        return explicit_text
    for name in names:
        value = str(metadata_value(chunk, name) or metadata_value(metadata, name) or "").strip()
        if value:
            return value
    return None
