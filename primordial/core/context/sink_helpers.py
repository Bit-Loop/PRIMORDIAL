from __future__ import annotations

from typing import Iterable

from primordial.core.context.envelopes import (
    RAG_CHUNK_FORMAT_SOURCE_TYPES,
    RAG_CHUNK_VULN_INTEL_SOURCE_TYPES,
    ContextEnvelope,
)
from primordial.core.context.evidence_shape import EVIDENCE_REF_PREFIX
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys
from primordial.core.context.sink_types import ContextSinkValidationResult
from primordial.core.context.source_types import NON_EVIDENCE_SOURCE_TYPES, RAG_ADVISORY_SOURCE_TYPES


def reject_sink_envelope(
    result: ContextSinkValidationResult,
    envelope: ContextEnvelope,
    message: str,
) -> None:
    result.rejected_refs.append(envelope.ref)
    result.errors.append(message)


def citations_with_prefixes(envelope: ContextEnvelope, prefixes: Iterable[str]) -> list[str]:
    normalized_prefixes = tuple(prefix.lower() for prefix in prefixes)
    return [
        citation
        for citation in (str(citation).strip() for citation in envelope.citations)
        if citation.lower().startswith(normalized_prefixes)
    ]


def non_evidence_proof_source_type(envelope: ContextEnvelope, kinds: frozenset[str]) -> str:
    if envelope.kind not in kinds:
        return ""
    source_types = {normalized_context_key(envelope.source_type), *_metadata_text_values(envelope, "source_type")}
    return next(iter(sorted(source_types & NON_EVIDENCE_SOURCE_TYPES)), "")


def non_advisory_rag_source_type(envelope: ContextEnvelope) -> str:
    if envelope.kind != "rag":
        return ""
    source_types = {normalized_context_key(envelope.source_type), *_metadata_text_values(envelope, "source_type")}
    if normalized_context_key(envelope.source_type) in RAG_ADVISORY_SOURCE_TYPES:
        source_types -= RAG_CHUNK_FORMAT_SOURCE_TYPES
    if normalized_context_key(envelope.source_type) == "vuln_intel":
        source_types -= RAG_CHUNK_VULN_INTEL_SOURCE_TYPES
    return next(iter(sorted(source_types - RAG_ADVISORY_SOURCE_TYPES)), "")


def sink_context_restriction_reject_reason(envelope: ContextEnvelope, sink: str) -> str:
    context_names = normalized_context_keys((sink, envelope.purpose))
    invalid_for = normalized_context_keys(envelope.invalid_for)
    if invalid_for & context_names:
        return f"invalid_for excludes {sink}"
    valid_for = normalized_context_keys(envelope.valid_for)
    if valid_for and not valid_for & context_names:
        return f"valid_for excludes {sink}"
    return ""


def unresolved_evidence_citations(
    envelope: ContextEnvelope,
    known_evidence_refs: Iterable[str] | None,
) -> list[str]:
    if known_evidence_refs is None:
        return []
    known_refs = {_canonical_evidence_ref(ref) for ref in known_evidence_refs if _canonical_evidence_ref(ref)}
    known_refs.add(envelope.ref)
    citations = citations_with_prefixes(envelope, (EVIDENCE_REF_PREFIX,))
    return sorted(set(citations) - known_refs)


def _metadata_text_values(envelope: ContextEnvelope, *names: str) -> set[str]:
    values: set[str] = set()
    for value in _metadata_values_from(envelope.metadata, *names):
        for item in _metadata_scalar_values(value):
            text = normalized_context_key(item)
            if text:
                values.add(text)
    return values


def _metadata_values_from(value: object, *names: str) -> list[object]:
    normalized_names = normalized_context_keys(names)
    if "source_type" in normalized_names:
        normalized_names.add("source_types")
    values: list[object] = []
    if isinstance(value, dict):
        items = value.items()
    elif isinstance(value, (frozenset, list, set, tuple)):
        for item in value:
            values.extend(_metadata_values_from(item, *names))
        return values
    else:
        return values
    for raw_key, item_value in items:
        if normalized_context_key(raw_key) in normalized_names:
            values.append(item_value)
        values.extend(_metadata_values_from(item_value, *names))
    return values


def _metadata_scalar_values(value: object) -> list[object]:
    if isinstance(value, dict):
        return []
    if isinstance(value, (frozenset, list, set, tuple)):
        values: list[object] = []
        for item in value:
            values.extend(_metadata_scalar_values(item))
        return values
    return [value]


def _canonical_evidence_ref(value: object) -> str:
    ref = str(value or "").strip()
    if ref.lower().startswith(EVIDENCE_REF_PREFIX):
        return f"{EVIDENCE_REF_PREFIX}{ref[len(EVIDENCE_REF_PREFIX):].strip()}"
    return ref
