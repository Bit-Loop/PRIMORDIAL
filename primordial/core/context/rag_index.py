from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from primordial.core.context.bindings import has_target_fact_marker
from primordial.core.context.citations import CitationValidator, PLACEHOLDER_RAG_REFS
from primordial.core.context.envelopes import (
    RAG_CHUNK_FORMAT_SOURCE_TYPES,
    RAG_CHUNK_VULN_INTEL_SOURCE_TYPES,
    ContextEnvelope,
)
from primordial.core.context.generated_exports import (
    GENERATED_EXPORT_KINDS,
    GENERATED_EXPORT_SOURCE_TYPES,
    has_generated_export_origin,
    has_generated_export_path,
    is_generated_export_path,
    is_generated_export_record,
)
from primordial.core.context.metadata_flags import metadata_value_is_false, raw_metadata_value
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys
from primordial.core.context.poison import has_context_flag
from primordial.core.context.source_markdown import has_source_markdown_path, is_source_markdown_path
from primordial.core.context.source_refs import (
    has_malformed_source_refs_metadata,
    placeholder_source_refs,
    source_refs_metadata_values,
    uncited_source_refs_metadata,
    unsupported_ai_derived_source_refs,
    unresolved_ai_derived_source_ref_errors,
)
from primordial.core.context.source_types import RAG_ADVISORY_SOURCE_TYPES


GENERATED_MODEL_OR_CHAT_SOURCE_TYPES = frozenset({"ai_output", "chat"})
GENERATED_MODEL_OR_CHAT_KINDS = frozenset({"model_summary"})
EVIDENCE_OR_AUTHORITY_KINDS = frozenset(
    {
        "approval",
        "authority",
        "evidence",
        "operator_intent",
        "policy_decision",
        "scope",
    }
)
EVIDENCE_OR_AUTHORITY_SOURCE_TYPES = frozenset({"runtime_state", "tool_output"})
EVIDENCE_OR_AUTHORITY_AUTHORITIES = frozenset({"authoritative", "canonical", "observed"})
TARGET_CONTEXT_LANE_KINDS = frozenset({"finding", "operator_note"})
DERIVED_PLANNING_KINDS = frozenset({"candidate_task", "hypothesis"})
COLLABORATION_REFERENCE_KINDS = frozenset({"ctfd_ref", "github_ref", "notion_ref"})
RECENT_ACTION_TRACE_KINDS = frozenset(
    {"action_trace", "blocked_action", "failure_trace", "primitive_run", "task_outcome"}
)
HIDDEN_SOLUTION_FLAGS = (
    "hidden_solution_material",
    "contains_hidden_solution",
    "contains_solution",
    "contains_raw_expected_flag",
)
RAW_SENSITIVE_MATERIAL_FLAGS = (
    "contains_sensitive_raw_target_evidence",
    "contains_raw_flag",
    "contains_secret",
    "contains_credential",
)
WRITEUP_SOURCE_TYPES = frozenset({"writeup"})
WRITEUP_FORBIDDEN_POLICIES = frozenset(
    {
        "closed_book",
        "closed-book",
        "forbid",
        "forbidden",
        "deny",
        "denied",
        "exclude",
        "excluded",
        "closed_book_excluded",
    }
)
CLOSED_BOOK_MODES = frozenset({"closed_book", "closed-book", "closed_book_mode"})
POSTMORTEM_MODES = frozenset({"postmortem", "postmortem_only", "postmortem-only"})
RAG_INDEX_ALLOWED_KINDS = frozenset({"rag"})
RAG_INDEX_ALLOWED_AUTHORITIES = frozenset({"advisory", "historical", "unverified"})
RAG_INDEX_ALLOWED_SOURCE_TYPES = RAG_ADVISORY_SOURCE_TYPES
RAG_INDEX_PLACEHOLDER_REFS = PLACEHOLDER_RAG_REFS


@dataclass(frozen=True, slots=True)
class RagIndexSinkDecision:
    action: str
    message: str = ""


def validate_rag_index_sink(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None = None,
    known_note_refs: Iterable[str] | None = None,
    known_rag_refs: Iterable[str] | None = None,
) -> RagIndexSinkDecision:
    for decision in (
        _rag_index_metadata_decision(envelope),
        _rag_index_lane_material_decision(envelope),
        _rag_index_source_ref_decision(
            envelope,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
            known_rag_refs=known_rag_refs,
        ),
        _rag_index_contract_decision(envelope, known_rag_refs=known_rag_refs),
    ):
        if decision is not None:
            return decision
    return RagIndexSinkDecision("accept")


def _rag_index_metadata_decision(envelope: ContextEnvelope) -> RagIndexSinkDecision | None:
    if envelope.kind in GENERATED_EXPORT_KINDS or envelope.source_type in GENERATED_EXPORT_SOURCE_TYPES:
        return RagIndexSinkDecision("reject", f"rag_index rejects generated export ref={envelope.ref}")
    if metadata_value_is_false(envelope, "ingest_allowed"):
        return RagIndexSinkDecision("reject", f"rag_index rejects ingest_allowed=false ref={envelope.ref}")
    if metadata_value_is_false(envelope, "operational_retrieval_allowed"):
        return RagIndexSinkDecision(
            "reject",
            f"rag_index rejects operational_retrieval_allowed=false ref={envelope.ref}",
        )
    restriction_reason = _rag_index_restriction_reject_reason(envelope)
    if restriction_reason:
        return RagIndexSinkDecision("reject", f"rag_index rejects {restriction_reason} ref={envelope.ref}")
    if is_generated_export_record(envelope):
        return RagIndexSinkDecision("reject", f"rag_index rejects generated export ref={envelope.ref}")
    if has_generated_export_origin(envelope):
        return RagIndexSinkDecision("reject", f"rag_index rejects generated export ref={envelope.ref}")
    if has_generated_export_path(envelope):
        return RagIndexSinkDecision("reject", f"rag_index rejects generated export ref={envelope.ref}")
    if is_generated_export_path(raw_metadata_value(envelope, "source_url")):
        return RagIndexSinkDecision("reject", f"rag_index rejects generated export ref={envelope.ref}")
    if has_source_markdown_path(envelope) or is_source_markdown_path(raw_metadata_value(envelope, "source_url")):
        return RagIndexSinkDecision("reject", f"rag_index rejects source Markdown ref={envelope.ref}")
    return None


def _rag_index_lane_material_decision(envelope: ContextEnvelope) -> RagIndexSinkDecision | None:
    if _is_generated_model_or_chat_material(envelope):
        return RagIndexSinkDecision(
            "reject",
            f"rag_index rejects generated model or chat material ref={envelope.ref}",
        )
    if _is_evidence_or_authority_lane_material(envelope):
        return RagIndexSinkDecision(
            "reject",
            f"rag_index rejects evidence or authority lane material ref={envelope.ref}",
        )
    if _context_kinds(envelope) & TARGET_CONTEXT_LANE_KINDS:
        return RagIndexSinkDecision(
            "reject",
            f"rag_index rejects target context lane material ref={envelope.ref}",
        )
    if _context_kinds(envelope) & DERIVED_PLANNING_KINDS:
        return RagIndexSinkDecision(
            "reject",
            f"rag_index rejects derived planning state ref={envelope.ref}",
        )
    if _context_kinds(envelope) & COLLABORATION_REFERENCE_KINDS:
        return RagIndexSinkDecision(
            "reject",
            f"rag_index rejects collaboration reference lane material ref={envelope.ref}",
        )
    if _context_kinds(envelope) & RECENT_ACTION_TRACE_KINDS:
        return RagIndexSinkDecision(
            "reject",
            f"rag_index rejects recent action trace lane material ref={envelope.ref}",
        )
    if has_context_flag(envelope, HIDDEN_SOLUTION_FLAGS):
        return RagIndexSinkDecision("reject", f"rag_index rejects hidden solution material ref={envelope.ref}")
    if has_context_flag(envelope, RAW_SENSITIVE_MATERIAL_FLAGS):
        return RagIndexSinkDecision("reject", f"rag_index rejects raw sensitive material ref={envelope.ref}")
    if has_target_fact_marker(envelope):
        return RagIndexSinkDecision("reject", f"rag_index rejects target fact material ref={envelope.ref}")
    return None


def _rag_index_source_ref_decision(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> RagIndexSinkDecision | None:
    source_ref_reason = _source_refs_reject_reason(
        envelope,
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )
    if source_ref_reason:
        return RagIndexSinkDecision("reject", f"rag_index rejects {source_ref_reason} ref={envelope.ref}")
    return None


def _rag_index_contract_decision(
    envelope: ContextEnvelope,
    *,
    known_rag_refs: Iterable[str] | None,
) -> RagIndexSinkDecision | None:
    if _context_source_types(envelope) & WRITEUP_SOURCE_TYPES and _writeup_policy_forbids_ingest(envelope):
        restriction = _writeup_restriction(envelope) or "<unspecified>"
        return RagIndexSinkDecision("reject", f"rag_index rejects writeup in {restriction} mode ref={envelope.ref}")
    unsupported_source_types = _unsupported_rag_index_source_types(envelope)
    if unsupported_source_types:
        source_type = next(iter(sorted(unsupported_source_types)))
        return RagIndexSinkDecision(
            "reject",
            f"rag_index requires advisory source_type ref={envelope.ref} source_type={source_type}",
        )
    if envelope.kind not in RAG_INDEX_ALLOWED_KINDS:
        return RagIndexSinkDecision(
            "reject",
            f"rag_index requires kind=rag ref={envelope.ref} kind={envelope.kind}",
        )
    if envelope.ref in RAG_INDEX_PLACEHOLDER_REFS:
        return RagIndexSinkDecision(
            "reject",
            f"rag_index requires explicit rag ref, got placeholder ref={envelope.ref}",
        )
    if envelope.authority not in RAG_INDEX_ALLOWED_AUTHORITIES:
        return RagIndexSinkDecision(
            "reject",
            f"rag_index requires advisory authority ref={envelope.ref} authority={envelope.authority}",
        )
    citations = CitationValidator(known_rag_refs=_known_rag_refs_for_index(envelope, known_rag_refs)).validate(
        [envelope]
    )
    if not citations.valid:
        return RagIndexSinkDecision("reject", "; ".join(citations.errors))
    return None


def _is_generated_model_or_chat_material(envelope: ContextEnvelope) -> bool:
    kinds = {envelope.kind, *_metadata_text_values(envelope, "kind", "kinds")}
    source_types = {envelope.source_type, *_metadata_text_values(envelope, "source_type", "source_types")}
    return bool(kinds & GENERATED_MODEL_OR_CHAT_KINDS) or bool(source_types & GENERATED_MODEL_OR_CHAT_SOURCE_TYPES)


def _context_kinds(envelope: ContextEnvelope) -> set[str]:
    return {envelope.kind, *_metadata_text_values(envelope, "kind", "kinds")}


def _context_source_types(envelope: ContextEnvelope) -> set[str]:
    return {envelope.source_type, *_metadata_text_values(envelope, "source_type", "source_types")}


def _unsupported_rag_index_source_types(envelope: ContextEnvelope) -> set[str]:
    source_types = _context_source_types(envelope)
    if envelope.source_type in RAG_ADVISORY_SOURCE_TYPES:
        source_types -= RAG_CHUNK_FORMAT_SOURCE_TYPES
    if envelope.source_type == "vuln_intel":
        source_types -= RAG_CHUNK_VULN_INTEL_SOURCE_TYPES
    return source_types - RAG_INDEX_ALLOWED_SOURCE_TYPES


def _is_evidence_or_authority_lane_material(envelope: ContextEnvelope) -> bool:
    kinds = _context_kinds(envelope)
    if kinds & EVIDENCE_OR_AUTHORITY_KINDS:
        return True
    source_types = _context_source_types(envelope)
    authorities = {envelope.authority, *_metadata_text_values(envelope, "authority", "authorities")}
    return (
        bool(source_types & EVIDENCE_OR_AUTHORITY_SOURCE_TYPES)
        and bool(authorities & EVIDENCE_OR_AUTHORITY_AUTHORITIES)
    )


def _rag_index_restriction_reject_reason(envelope: ContextEnvelope) -> str:
    context_names = normalized_context_keys(("rag_index", envelope.purpose))
    invalid_for = normalized_context_keys(envelope.invalid_for)
    if invalid_for & context_names:
        return "invalid_for excludes rag_index"
    valid_for = normalized_context_keys(envelope.valid_for)
    if valid_for and not valid_for & context_names:
        return "valid_for excludes rag_index"
    return ""


def _source_refs_reject_reason(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> str:
    if has_malformed_source_refs_metadata(envelope):
        return "malformed source_refs"
    unsupported_refs = unsupported_ai_derived_source_refs(source_refs_metadata_values(envelope))
    if unsupported_refs:
        return f"unsupported source_refs: {', '.join(unsupported_refs)}"
    placeholder_refs = placeholder_source_refs(source_refs_metadata_values(envelope))
    if placeholder_refs:
        return f"placeholder source_refs: {', '.join(placeholder_refs)}"
    uncited_refs = uncited_source_refs_metadata(envelope)
    if uncited_refs:
        return f"uncited source_refs: {', '.join(uncited_refs)}"
    unresolved_refs = unresolved_ai_derived_source_ref_errors(
        envelope.ref,
        source_refs_metadata_values(envelope),
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=_known_rag_refs_for_index(envelope, known_rag_refs),
    )
    if unresolved_refs:
        return "; ".join(unresolved_refs)
    return ""


def _writeup_policy_forbids_ingest(envelope: ContextEnvelope) -> bool:
    return bool(_writeup_policy_restrictions(envelope))


def _writeup_restriction(envelope: ContextEnvelope) -> str:
    restrictions = _writeup_policy_restrictions(envelope) - {"writeups_allowed=false"}
    return next(iter(sorted(restrictions)), "")


def _writeup_policy_restrictions(envelope: ContextEnvelope) -> set[str]:
    restrictions: set[str] = set()
    modes = _metadata_text_values(envelope, "benchmark_mode", "mode")
    restrictions.update(modes & CLOSED_BOOK_MODES)
    if metadata_value_is_false(envelope, "writeups_allowed"):
        restrictions.add("writeups_allowed=false")
    policies = _metadata_text_values(envelope, "writeup_access_policy")
    postmortem_only_policies = policies & {"postmortem_only", "postmortem-only"}
    if postmortem_only_policies and not _is_postmortem_scoped(envelope):
        restrictions.update(postmortem_only_policies)
    restrictions.update(policies & WRITEUP_FORBIDDEN_POLICIES)
    return restrictions


def _is_postmortem_scoped(envelope: ContextEnvelope) -> bool:
    scoped_values = _metadata_text_values(envelope, "benchmark_mode", "mode", "purpose")
    scoped_values.add(envelope.purpose)
    return bool(scoped_values & POSTMORTEM_MODES)


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


def _known_rag_refs_for_index(
    envelope: ContextEnvelope,
    known_rag_refs: Iterable[str] | None,
) -> set[str] | None:
    if known_rag_refs is None:
        return None
    refs = {str(ref).strip() for ref in known_rag_refs if str(ref).strip()}
    refs.add(envelope.ref)
    return refs
