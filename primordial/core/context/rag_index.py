from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from primordial.core.context.bindings import has_target_fact_marker
from primordial.core.context.citations import CitationValidator, PLACEHOLDER_RAG_REFS
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.generated_exports import has_generated_export_origin, is_generated_export_record
from primordial.core.context.metadata_flags import metadata_value_is_false, raw_metadata_value
from primordial.core.context.normalization import normalized_context_key
from primordial.core.context.poison import has_context_flag
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
        "forbid",
        "forbidden",
        "deny",
        "denied",
        "exclude",
        "excluded",
        "closed_book_excluded",
    }
)
CLOSED_BOOK_MODES = frozenset({"closed_book", "closed-book"})
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
    known_rag_refs: Iterable[str] | None = None,
) -> RagIndexSinkDecision:
    if is_generated_export_record(envelope):
        return RagIndexSinkDecision("reject", f"rag_index rejects generated export ref={envelope.ref}")
    if metadata_value_is_false(envelope, "ingest_allowed"):
        return RagIndexSinkDecision("reject", f"rag_index rejects ingest_allowed=false ref={envelope.ref}")
    if metadata_value_is_false(envelope, "operational_retrieval_allowed"):
        return RagIndexSinkDecision(
            "reject",
            f"rag_index rejects operational_retrieval_allowed=false ref={envelope.ref}",
        )
    if has_generated_export_origin(envelope):
        return RagIndexSinkDecision("reject", f"rag_index rejects generated export ref={envelope.ref}")
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
    if envelope.kind in TARGET_CONTEXT_LANE_KINDS:
        return RagIndexSinkDecision(
            "reject",
            f"rag_index rejects target context lane material ref={envelope.ref}",
        )
    if envelope.kind in DERIVED_PLANNING_KINDS:
        return RagIndexSinkDecision(
            "reject",
            f"rag_index rejects derived planning state ref={envelope.ref}",
        )
    if envelope.kind in COLLABORATION_REFERENCE_KINDS:
        return RagIndexSinkDecision(
            "reject",
            f"rag_index rejects collaboration reference lane material ref={envelope.ref}",
        )
    if envelope.kind in RECENT_ACTION_TRACE_KINDS:
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
    if envelope.source_type in WRITEUP_SOURCE_TYPES and _writeup_policy_forbids_ingest(envelope):
        mode = _metadata_value(envelope, "benchmark_mode") or _metadata_value(envelope, "mode") or "<unspecified>"
        return RagIndexSinkDecision("reject", f"rag_index rejects writeup in {mode} mode ref={envelope.ref}")
    if envelope.source_type not in RAG_INDEX_ALLOWED_SOURCE_TYPES:
        return RagIndexSinkDecision(
            "reject",
            f"rag_index requires advisory source_type ref={envelope.ref} source_type={envelope.source_type}",
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
    return RagIndexSinkDecision("accept")


def _is_generated_model_or_chat_material(envelope: ContextEnvelope) -> bool:
    return envelope.kind in GENERATED_MODEL_OR_CHAT_KINDS or envelope.source_type in GENERATED_MODEL_OR_CHAT_SOURCE_TYPES


def _is_evidence_or_authority_lane_material(envelope: ContextEnvelope) -> bool:
    if envelope.kind in EVIDENCE_OR_AUTHORITY_KINDS:
        return True
    return (
        envelope.source_type in EVIDENCE_OR_AUTHORITY_SOURCE_TYPES
        and envelope.authority in EVIDENCE_OR_AUTHORITY_AUTHORITIES
    )


def _writeup_policy_forbids_ingest(envelope: ContextEnvelope) -> bool:
    if _metadata_value(envelope, "benchmark_mode") in CLOSED_BOOK_MODES:
        return True
    if _metadata_value(envelope, "mode") in CLOSED_BOOK_MODES:
        return True
    if metadata_value_is_false(envelope, "writeups_allowed"):
        return True
    policy = _metadata_value(envelope, "writeup_access_policy")
    return policy in WRITEUP_FORBIDDEN_POLICIES


def _metadata_value(envelope: ContextEnvelope, name: str) -> str:
    return normalized_context_key(raw_metadata_value(envelope, name))


def _known_rag_refs_for_index(
    envelope: ContextEnvelope,
    known_rag_refs: Iterable[str] | None,
) -> set[str] | None:
    if known_rag_refs is None:
        return None
    refs = {str(ref).strip() for ref in known_rag_refs if str(ref).strip()}
    refs.add(envelope.ref)
    return refs
