from __future__ import annotations

from typing import Iterable

from primordial.core.context.assembler_roles import safety_sensitive_omission_reason
from primordial.core.context.citations import CitationValidator, NON_EVIDENCE_PROOF_CITATION_PREFIXES, PLACEHOLDER_RAG_REFS
from primordial.core.context.envelopes import (
    RAG_CHUNK_FORMAT_SOURCE_TYPES,
    RAG_CHUNK_VULN_INTEL_SOURCE_TYPES,
    ContextEnvelope,
)
from primordial.core.context.evidence_shape import EVIDENCE_CONTEXT_AUTHORITIES
from primordial.core.context.generated_exports import (
    has_generated_export_path,
    is_generated_export_context,
    is_generated_export_path,
)
from primordial.core.context.metadata_flags import metadata_value_is_false, raw_metadata_value
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys
from primordial.core.context.operator_notes import RAW_CHAT_SOURCE_TYPES, operator_note_source_omission_reason
from primordial.core.context.source_markdown import is_source_markdown_context
from primordial.core.context.source_refs import (
    EVIDENCE_REF_PREFIX,
    NOTE_REF_PREFIX,
    RAG_REF_PREFIX,
    source_refs_metadata_errors,
)
from primordial.core.context.source_types import EVIDENCE_PROOF_KINDS, NON_EVIDENCE_SOURCE_TYPES, RAG_ADVISORY_SOURCE_TYPES
from primordial.core.context.writeup_policy import prompt_writeup_omission_reason


PROMPT_SINK = "prompt"


def current_evidence_refs(
    envelopes: Iterable[ContextEnvelope],
    *,
    target_id: str | None,
    active_generation_id: str | None,
    purpose: str,
    role: str,
) -> set[str]:
    role_name = normalized_context_key(role)
    refs: set[str] = set()
    for envelope in envelopes:
        if envelope.kind != "evidence":
            continue
        if not envelope.ref.startswith(EVIDENCE_REF_PREFIX):
            continue
        if _context_source_types(envelope) & NON_EVIDENCE_SOURCE_TYPES:
            continue
        if safety_sensitive_omission_reason(envelope, role=role_name):
            continue
        if _shared_context_omission_reason(envelope, purpose=purpose, role=role_name):
            continue
        if _evidence_proof_shape_omission_reason(envelope):
            continue
        if source_refs_metadata_errors(envelope):
            continue
        if _has_non_evidence_proof_citation_support(envelope):
            continue
        if target_id and envelope.target_id != target_id:
            continue
        if active_generation_id and envelope.active_generation_id != active_generation_id:
            continue
        refs.add(envelope.ref)
    return refs


def current_rag_refs(
    envelopes: Iterable[ContextEnvelope],
    *,
    target_id: str | None,
    active_generation_id: str | None,
    purpose: str,
    role: str,
) -> set[str]:
    role_name = normalized_context_key(role)
    refs: set[str] = set()
    for envelope in envelopes:
        if envelope.kind != "rag":
            continue
        if not envelope.ref.startswith(RAG_REF_PREFIX):
            continue
        if _non_advisory_rag_source_type(envelope):
            continue
        if safety_sensitive_omission_reason(envelope, role=role_name):
            continue
        if prompt_writeup_omission_reason(envelope, role=role_name):
            continue
        if target_id and envelope.target_id and envelope.target_id != target_id:
            continue
        if active_generation_id and envelope.active_generation_id and envelope.active_generation_id != active_generation_id:
            continue
        if _has_placeholder_rag_ref(envelope):
            continue
        if not CitationValidator().validate([envelope]).valid:
            continue
        if source_refs_metadata_errors(envelope):
            continue
        if _shared_context_omission_reason(envelope, purpose=purpose, role=role_name):
            continue
        refs.add(envelope.ref)
    return refs


def current_note_refs(
    envelopes: Iterable[ContextEnvelope],
    *,
    target_id: str | None,
    active_generation_id: str | None,
    purpose: str,
    role: str,
) -> set[str]:
    role_name = normalized_context_key(role)
    refs: set[str] = set()
    for envelope in envelopes:
        if envelope.kind != "operator_note":
            continue
        if not envelope.ref.startswith(NOTE_REF_PREFIX):
            continue
        if operator_note_source_omission_reason(envelope):
            continue
        if safety_sensitive_omission_reason(envelope, role=role_name):
            continue
        if target_id and envelope.target_id and envelope.target_id != target_id:
            continue
        if active_generation_id and envelope.active_generation_id and envelope.active_generation_id != active_generation_id:
            continue
        if _shared_context_omission_reason(envelope, purpose=purpose, role=role_name):
            continue
        if source_refs_metadata_errors(envelope):
            continue
        refs.add(envelope.ref)
    return refs


def prompt_context_omission_reason(envelope: ContextEnvelope, *, purpose: str, role: str) -> str:
    if (
        is_generated_export_context(envelope)
        or has_generated_export_path(envelope)
        or is_generated_export_path(raw_metadata_value(envelope, "source_url"))
    ):
        return "generated_export"
    if is_source_markdown_context(envelope):
        return "source_markdown"
    if metadata_value_is_false(envelope, "operational_retrieval_allowed"):
        return "operational_retrieval_disabled"
    if _is_raw_chat_context(envelope):
        return "raw_chat_context"
    validity_reason = _validity_omission_reason(envelope, purpose=purpose, role=role)
    if validity_reason:
        return validity_reason
    return "sink_mismatch" if _has_prompt_sink_mismatch(envelope) else ""


def _shared_context_omission_reason(envelope: ContextEnvelope, *, purpose: str, role: str) -> bool:
    return bool(prompt_context_omission_reason(envelope, purpose=purpose, role=role))


def _evidence_proof_shape_omission_reason(envelope: ContextEnvelope) -> str:
    if envelope.authority not in EVIDENCE_CONTEXT_AUTHORITIES:
        return "invalid_evidence_authority"
    return "" if envelope.ref.startswith(EVIDENCE_REF_PREFIX) else "invalid_evidence_ref"


def _has_non_evidence_proof_citation_support(envelope: ContextEnvelope) -> bool:
    prefixes = tuple(prefix.lower() for prefix in NON_EVIDENCE_PROOF_CITATION_PREFIXES)
    return envelope.kind in EVIDENCE_PROOF_KINDS and any(
        str(citation).strip().lower().startswith(prefixes) for citation in envelope.citations
    )


def _has_placeholder_rag_ref(envelope: ContextEnvelope) -> bool:
    refs = [envelope.ref, *envelope.citations]
    return any(str(ref).strip().lower() in PLACEHOLDER_RAG_REFS for ref in refs)


def _validity_omission_reason(envelope: ContextEnvelope, *, purpose: str, role: str) -> str:
    context_names = normalized_context_keys((purpose, role, PROMPT_SINK))
    invalid_for = normalized_context_keys(envelope.invalid_for)
    if invalid_for & context_names:
        return "invalid_for_context"
    valid_for = normalized_context_keys(envelope.valid_for)
    if valid_for and not valid_for & context_names:
        return "not_valid_for_context"
    return ""


def _is_raw_chat_context(envelope: ContextEnvelope) -> bool:
    return bool(_context_source_types(envelope) & RAW_CHAT_SOURCE_TYPES)


def _has_prompt_sink_mismatch(envelope: ContextEnvelope) -> bool:
    return normalized_context_key(envelope.sink) != PROMPT_SINK


def _context_source_types(envelope: ContextEnvelope) -> set[str]:
    return {normalized_context_key(envelope.source_type), *_metadata_text_values(envelope, "source_type")}


def _non_advisory_rag_source_type(envelope: ContextEnvelope) -> str:
    if envelope.kind != "rag":
        return ""
    source_types = _context_source_types(envelope)
    envelope_source_type = normalized_context_key(envelope.source_type)
    if envelope_source_type in RAG_ADVISORY_SOURCE_TYPES:
        source_types -= RAG_CHUNK_FORMAT_SOURCE_TYPES
    if envelope_source_type == "vuln_intel":
        source_types -= RAG_CHUNK_VULN_INTEL_SOURCE_TYPES
    return next(iter(sorted(source_types - RAG_ADVISORY_SOURCE_TYPES)), "")


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
