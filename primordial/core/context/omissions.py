from __future__ import annotations

from primordial.core.context.bindings import has_target_fact_marker
from primordial.core.context.citations import CitationValidator, NON_EVIDENCE_PROOF_CITATION_PREFIXES, PLACEHOLDER_RAG_REFS
from primordial.core.context.current_refs import operator_note_source_omission_reason, prompt_context_omission_reason
from primordial.core.context.evidence_shape import EVIDENCE_CONTEXT_AUTHORITIES, FINDING_REF_PREFIX
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.generated_exports import (
    has_generated_export_path,
    is_generated_export_context,
    is_generated_export_path,
)
from primordial.core.context.metadata_flags import metadata_value_is_false, raw_metadata_value
from primordial.core.context.normalization import normalized_context_key
from primordial.core.context.assembler_roles import role_specific_omission_reason, safety_sensitive_omission_reason
from primordial.core.context.source_markdown import is_source_markdown_context
from primordial.core.context.source_refs import (
    placeholder_source_refs,
    source_refs_metadata_errors,
    source_refs_metadata_values,
    unresolved_ai_derived_source_ref_errors,
)
from primordial.core.context.source_types import (
    COLLABORATION_REFERENCE_KINDS,
    COLLABORATION_SOURCE_TYPES,
    EVIDENCE_PROOF_KINDS,
    NON_EVIDENCE_SOURCE_TYPES,
    RAG_ADVISORY_SOURCE_TYPES,
    TRUTH_LIKE_AUTHORITIES,
)
from primordial.core.context.task_metadata import task_metadata_errors
from primordial.core.context.writeup_policy import prompt_writeup_omission_reason


EVIDENCE_CITATION_PREFIX = "evidence:"
CURRENT_TARGET_BOUND_KINDS = frozenset({"evidence", "finding"})
MODEL_DERIVED_TARGET_BOUND_KINDS = frozenset({"model_summary", "hypothesis", "candidate_task"})
POLICY_GATE_MODEL_DERIVED_KINDS = frozenset({"candidate_task"})
POLICY_GATE_TARGET_BOUND_AUTHORITY_KINDS = frozenset({"approval", "policy_decision", "scope", "target_status"})
POLICY_GATE_CURRENT_TARGET_BOUND_KINDS = POLICY_GATE_MODEL_DERIVED_KINDS | POLICY_GATE_TARGET_BOUND_AUTHORITY_KINDS
CTFD_REFERENCE_KINDS = frozenset({"ctfd_ref", "challenge_metadata", "scoreboard_projection", "solve_status", "submission_result"})
ROLE_FORBIDDEN_SECTIONS = {
    "evidence_reviewer": frozenset({"RAG_ADVISORY", "MODEL_DERIVED", "COLLABORATION_REFS"}),
    "policy_gate": frozenset({"RAG_ADVISORY", "COLLABORATION_REFS", "OPERATOR_NOTES"}),
}


def omission_reason(
    envelope: ContextEnvelope,
    *,
    target_id: str | None,
    active_generation_id: str | None,
    known_evidence_refs: set[str],
    known_note_refs: set[str],
    known_rag_refs: set[str],
    purpose: str,
    role: str,
    section_name: str,
) -> str:
    role_name = normalized_context_key(role)
    prompt_context_reason = prompt_context_omission_reason(envelope, purpose=purpose, role=role_name)
    reason = _early_omission_reason(envelope, target_id=target_id, role_name=role_name)
    if reason:
        return reason
    reason = _source_ref_omission_reason(
        envelope,
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )
    if reason:
        return reason
    reason = _authority_omission_reason(envelope)
    if reason:
        return reason
    reason = _binding_omission_reason(
        envelope,
        target_id=target_id,
        active_generation_id=active_generation_id,
        role_name=role_name,
    )
    if reason:
        return reason
    return _late_omission_reason(
        envelope,
        role_name=role_name,
        section_name=section_name,
        active_generation_id=active_generation_id,
        known_evidence_refs=known_evidence_refs,
        known_rag_refs=known_rag_refs,
        prompt_context_reason=prompt_context_reason,
    )


def is_generated_export_source(envelope: ContextEnvelope) -> bool:
    return (
        is_generated_export_context(envelope)
        or has_generated_export_path(envelope)
        or is_generated_export_path(raw_metadata_value(envelope, "source_url"))
    )


def is_historical(envelope: ContextEnvelope, *, active_generation_id: str | None) -> bool:
    return bool(active_generation_id and envelope.active_generation_id and envelope.active_generation_id != active_generation_id)


def _early_omission_reason(envelope: ContextEnvelope, *, target_id: str | None, role_name: str) -> str:
    if target_id and envelope.target_id and envelope.target_id != target_id:
        return "wrong_target"
    if _has_placeholder_rag_ref(envelope):
        return "placeholder_rag_ref"
    if placeholder_source_refs(envelope.citations):
        return "invalid_citation"
    for reason in (
        safety_sensitive_omission_reason(envelope, role=role_name),
        prompt_writeup_omission_reason(envelope, role=role_name),
    ):
        if reason:
            return reason
    if is_generated_export_source(envelope):
        return "generated_export"
    if is_source_markdown_context(envelope):
        return "source_markdown"
    if metadata_value_is_false(envelope, "operational_retrieval_allowed"):
        return "operational_retrieval_disabled"
    return _evidence_proof_shape_omission_reason(envelope) or operator_note_source_omission_reason(envelope)


def _source_ref_omission_reason(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: set[str],
    known_note_refs: set[str],
    known_rag_refs: set[str],
) -> str:
    if envelope.kind == "rag" and has_target_fact_marker(envelope):
        return "target_fact_rag"
    if envelope.kind in {"operator_note", "rag"} | EVIDENCE_PROOF_KINDS | MODEL_DERIVED_TARGET_BOUND_KINDS:
        if source_refs_metadata_errors(envelope) or unresolved_ai_derived_source_ref_errors(
            envelope.ref,
            source_refs_metadata_values(envelope),
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs if envelope.kind not in EVIDENCE_PROOF_KINDS else None,
            known_rag_refs=known_rag_refs if envelope.kind not in EVIDENCE_PROOF_KINDS else None,
        ):
            return "invalid_citation"
    if not CitationValidator().validate([envelope]).valid or _has_non_evidence_proof_citation_support(envelope):
        return "invalid_citation"
    return ""


def _authority_omission_reason(envelope: ContextEnvelope) -> str:
    if _is_proof_from_non_evidence_source(envelope):
        return "non_evidence_source"
    if _is_ctfd_truth_like_authority(envelope):
        return "ctfd_truth_like_authority"
    if _is_collaboration_truth_like_authority(envelope):
        return "collaboration_truth_like_authority"
    if envelope.kind == "rag" and envelope.source_type not in RAG_ADVISORY_SOURCE_TYPES:
        return "non_advisory_rag_source"
    return ""


def _binding_omission_reason(
    envelope: ContextEnvelope,
    *,
    target_id: str | None,
    active_generation_id: str | None,
    role_name: str,
) -> str:
    if target_id and _requires_current_target_binding(envelope, role=role_name) and not envelope.target_id:
        return "missing_target_binding"
    if active_generation_id and _requires_current_target_binding(envelope, role=role_name) and not envelope.active_generation_id:
        return "missing_generation_binding"
    return ""


def _late_omission_reason(
    envelope: ContextEnvelope,
    *,
    role_name: str,
    section_name: str,
    active_generation_id: str | None,
    known_evidence_refs: set[str],
    known_rag_refs: set[str],
    prompt_context_reason: str,
) -> str:
    if envelope.kind != "rag" and not CitationValidator(known_evidence_refs=known_evidence_refs, known_rag_refs=known_rag_refs).validate([envelope]).valid:
        return "invalid_citation"
    if role_name == "policy_gate" and is_historical(envelope, active_generation_id=active_generation_id):
        return "stale_generation"
    if prompt_context_reason:
        return prompt_context_reason
    if envelope.kind == "rag" and not is_historical(envelope, active_generation_id=active_generation_id):
        if not CitationValidator(known_evidence_refs=known_evidence_refs, known_rag_refs=known_rag_refs).validate([envelope]).valid:
            return "invalid_citation"
    if role_name != "policy_gate" and envelope.kind == "candidate_task" and task_metadata_errors(envelope, known_evidence_refs=known_evidence_refs):
        return "task_metadata_invalid"
    return role_specific_omission_reason(envelope, role=role_name, section_name=section_name) or (
        "role_forbidden" if section_name in ROLE_FORBIDDEN_SECTIONS.get(role_name, frozenset()) else ""
    )


def _requires_current_target_binding(envelope: ContextEnvelope, *, role: str) -> bool:
    return envelope.kind in CURRENT_TARGET_BOUND_KINDS or (
        role == "policy_gate" and envelope.kind in POLICY_GATE_CURRENT_TARGET_BOUND_KINDS
    ) or (
        envelope.kind in MODEL_DERIVED_TARGET_BOUND_KINDS
        and any(str(citation).strip().startswith(EVIDENCE_CITATION_PREFIX) for citation in envelope.citations)
    )


def _has_placeholder_rag_ref(envelope: ContextEnvelope) -> bool:
    refs = [envelope.ref, *envelope.citations]
    return any(str(ref).strip().lower() in PLACEHOLDER_RAG_REFS for ref in refs)


def _is_proof_from_non_evidence_source(envelope: ContextEnvelope) -> bool:
    return envelope.kind in EVIDENCE_PROOF_KINDS and envelope.source_type in NON_EVIDENCE_SOURCE_TYPES


def _evidence_proof_shape_omission_reason(envelope: ContextEnvelope) -> str:
    if envelope.kind != "evidence":
        return "invalid_finding_ref" if envelope.kind == "finding" and not envelope.ref.startswith(FINDING_REF_PREFIX) else ""
    if envelope.authority not in EVIDENCE_CONTEXT_AUTHORITIES:
        return "invalid_evidence_authority"
    return "" if envelope.ref.startswith(EVIDENCE_CITATION_PREFIX) else "invalid_evidence_ref"


def _has_non_evidence_proof_citation_support(envelope: ContextEnvelope) -> bool:
    prefixes = tuple(prefix.lower() for prefix in NON_EVIDENCE_PROOF_CITATION_PREFIXES)
    return envelope.kind in EVIDENCE_PROOF_KINDS and any(
        str(citation).strip().lower().startswith(prefixes) for citation in envelope.citations
    )


def _is_ctfd_truth_like_authority(envelope: ContextEnvelope) -> bool:
    return (
        normalized_context_key(envelope.source_type) == "ctfd"
        or normalized_context_key(envelope.kind) in CTFD_REFERENCE_KINDS
    ) and normalized_context_key(envelope.authority) in TRUTH_LIKE_AUTHORITIES


def _is_collaboration_truth_like_authority(envelope: ContextEnvelope) -> bool:
    return normalized_context_key(envelope.authority) in TRUTH_LIKE_AUTHORITIES and (
        normalized_context_key(envelope.source_type) in COLLABORATION_SOURCE_TYPES
        or normalized_context_key(envelope.kind) in COLLABORATION_REFERENCE_KINDS
    )
