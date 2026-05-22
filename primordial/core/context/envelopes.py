from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
from typing import Any

from primordial.core.context.normalization import normalized_context_key
from primordial.core.domain.models import utc_now


PLACEHOLDER_RAG_CITATION_SUFFIXES = frozenset({"none", "null", "unknown"})


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
        self.ref = str(self.ref or "").strip()
        self.kind = normalized_context_key(self.kind)
        self.authority = normalized_context_key(self.authority)
        self.source_type = normalized_context_key(self.source_type)
        self.purpose = normalized_context_key(self.purpose)
        self.sink = normalized_context_key(self.sink)
        self.valid_for = _normalized_list(self.valid_for, lower=True, name="valid_for")
        self.invalid_for = _normalized_list(self.invalid_for, lower=True, name="invalid_for")
        self.poison_flags = _normalized_list(self.poison_flags, lower=True, name="poison_flags")
        self.citations = _normalized_list(self.citations, name="citations")
        if self.metadata is None:
            self.metadata = {}
        elif isinstance(self.metadata, Mapping):
            self.metadata = dict(self.metadata)
        else:
            raise ValueError("metadata must be a mapping")
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
        citation = _rag_citation_id(chunk, metadata, chunk_id)
        text = str(chunk.get("text") or chunk.get("retrieval_text") or chunk.get("excerpt") or "")
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
            source_type=str(
                metadata.get("source_type")
                or chunk.get("source_type")
                or metadata.get("corpus_type")
                or chunk.get("corpus_type")
                or "methodology_doc"
            ),
            target_id=envelope_target_id,
            active_generation_id=envelope_generation_id,
            corpus=str(metadata.get("corpus_type") or chunk.get("corpus_type") or ""),
            domain=str(metadata.get("domain") or chunk.get("domain") or ""),
            purpose=purpose,
            sink=sink,
            valid_for=_list_field(chunk, metadata, "valid_for"),
            invalid_for=_list_field(chunk, metadata, "invalid_for"),
            citations=[citation] if citation else [],
            content=text,
            poison_flags=_list_field(chunk, metadata, "poison_flags"),
            metadata=dict(metadata),
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
    for candidate in (chunk.get("citation_id"), metadata.get("citation_id"), chunk_id, "unknown"):
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
    value = chunk.get(name)
    if value is None:
        value = metadata.get(name)
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
        value = str(chunk.get(name) or metadata.get(name) or "").strip()
        if value:
            return value
    return None
