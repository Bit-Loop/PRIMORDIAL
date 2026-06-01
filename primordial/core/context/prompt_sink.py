from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from primordial.core.context.bindings import current_context_binding_error, has_target_fact_marker
from primordial.core.context.citations import CitationValidator
from primordial.core.context.current_refs import operator_note_source_omission_reason
from primordial.core.context.evidence_shape import (
    EVIDENCE_REF_PREFIX,
    FINDING_REF_PREFIX,
    evidence_shape_omission_reason,
    finding_shape_omission_reason,
)
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.generated_exports import (
    has_generated_export_path,
    is_generated_export_context,
    is_generated_export_path,
)
from primordial.core.context.metadata_flags import metadata_value_is_false, raw_metadata_value
from primordial.core.context.source_markdown import has_source_markdown_path, is_source_markdown_path
from primordial.core.context.source_refs import (
    placeholder_source_refs,
    source_refs_metadata_errors,
    source_refs_metadata_values,
    unresolved_ai_derived_source_ref_errors,
)
from primordial.core.context.writeup_policy import prompt_writeup_omission_reason


CitationPrefixCheck = Callable[[ContextEnvelope, Iterable[str]], list[str]]
ContextRestrictionCheck = Callable[[ContextEnvelope, str], str]
NonEvidenceProofCheck = Callable[[ContextEnvelope, frozenset[str]], str]
NonAdvisoryRagCheck = Callable[[ContextEnvelope], str]


@dataclass(frozen=True, slots=True)
class PromptSinkChecks:
    evidence_kinds: frozenset[str]
    evidence_context_authorities: frozenset[str]
    disallowed_evidence_citation_prefixes: Iterable[str]
    prompt_raw_chat_source_types: frozenset[str]
    prompt_ai_derived_kinds: frozenset[str]
    citations_with_prefixes: CitationPrefixCheck
    context_restriction_reject_reason: ContextRestrictionCheck
    non_evidence_proof_source_type: NonEvidenceProofCheck
    non_advisory_rag_source_type: NonAdvisoryRagCheck


@dataclass(frozen=True, slots=True)
class PromptSinkDecision:
    action: str
    message: str = ""


def validate_prompt_sink(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
    checks: PromptSinkChecks,
) -> PromptSinkDecision:
    for decision in (
        _shape_and_binding_decision(envelope, checks),
        _context_material_decision(envelope, checks),
        _operator_note_decision(envelope, known_evidence_refs, known_note_refs, known_rag_refs),
        _rag_decision(envelope, known_evidence_refs, known_note_refs, known_rag_refs, checks),
        _proof_record_decision(envelope, known_evidence_refs, checks),
        _ai_derived_decision(envelope, known_evidence_refs, known_note_refs, known_rag_refs, checks),
        _citation_decision(envelope, known_evidence_refs, known_rag_refs),
    ):
        if decision is not None:
            return decision
    return PromptSinkDecision("accept")


def _shape_and_binding_decision(envelope: ContextEnvelope, checks: PromptSinkChecks) -> PromptSinkDecision | None:
    evidence_shape_reason = evidence_shape_omission_reason(
        envelope,
        allowed_authorities=checks.evidence_context_authorities,
    )
    if evidence_shape_reason == "ref":
        return _reject(f"prompt sink requires {EVIDENCE_REF_PREFIX}<id> ref, got {envelope.ref}")
    if evidence_shape_reason:
        return _reject(f"prompt sink rejects evidence {evidence_shape_reason} ref={envelope.ref}")
    finding_shape_reason = finding_shape_omission_reason(envelope)
    if finding_shape_reason == "ref":
        return _reject(f"prompt sink requires {FINDING_REF_PREFIX}<id> ref, got {envelope.ref}")
    if envelope.kind == "rag" and has_target_fact_marker(envelope):
        return _reject(f"prompt sink rejects target fact rag ref={envelope.ref}")
    binding_reason = current_context_binding_error(envelope, proof_records=True, target_facts=True)
    if binding_reason:
        return _reject(f"prompt sink rejects {binding_reason} context ref={envelope.ref}")
    return None


def _context_material_decision(envelope: ContextEnvelope, checks: PromptSinkChecks) -> PromptSinkDecision | None:
    if _is_generated_export_material(envelope):
        return _reject(f"prompt sink rejects generated_export ref={envelope.ref}")
    if has_source_markdown_path(envelope) or is_source_markdown_path(raw_metadata_value(envelope, "source_url")):
        return _reject(f"prompt sink rejects source_markdown ref={envelope.ref}")
    if metadata_value_is_false(envelope, "operational_retrieval_allowed"):
        return _reject(f"prompt sink rejects operational_retrieval_allowed=false ref={envelope.ref}")
    writeup_reason = prompt_writeup_omission_reason(envelope, role="ctf_solver_orchestrator")
    if writeup_reason:
        return _reject(f"prompt sink rejects {writeup_reason} ref={envelope.ref}")
    if envelope.source_type in checks.prompt_raw_chat_source_types:
        return _reject(f"prompt sink rejects raw_chat_context ref={envelope.ref}")
    restriction_reason = checks.context_restriction_reject_reason(envelope, "prompt")
    if restriction_reason:
        return _reject(f"prompt sink rejects {restriction_reason} ref={envelope.ref}")
    note_source_reason = operator_note_source_omission_reason(envelope)
    if note_source_reason:
        return _reject(f"prompt sink rejects {note_source_reason} ref={envelope.ref}")
    return None


def _operator_note_decision(
    envelope: ContextEnvelope,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> PromptSinkDecision | None:
    if envelope.kind != "operator_note":
        return None
    return _source_ref_decision(
        envelope,
        error_prefix="prompt sink rejects",
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )


def _rag_decision(
    envelope: ContextEnvelope,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
    checks: PromptSinkChecks,
) -> PromptSinkDecision | None:
    non_advisory_rag_source_type = checks.non_advisory_rag_source_type(envelope)
    if non_advisory_rag_source_type:
        return _reject(
            "prompt sink rejects non_advisory_rag_source "
            f"source_type={non_advisory_rag_source_type} ref={envelope.ref}"
        )
    if envelope.kind != "rag":
        return None
    return _source_ref_decision(
        envelope,
        error_prefix="prompt sink rejects",
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )


def _proof_record_decision(
    envelope: ContextEnvelope,
    known_evidence_refs: Iterable[str] | None,
    checks: PromptSinkChecks,
) -> PromptSinkDecision | None:
    evidence_decision = _evidence_record_decision(envelope, known_evidence_refs, checks)
    if evidence_decision is not None:
        return evidence_decision
    return _finding_record_decision(envelope, known_evidence_refs, checks)


def _evidence_record_decision(
    envelope: ContextEnvelope,
    known_evidence_refs: Iterable[str] | None,
    checks: PromptSinkChecks,
) -> PromptSinkDecision | None:
    non_evidence_source_type = checks.non_evidence_proof_source_type(envelope, checks.evidence_kinds)
    if non_evidence_source_type:
        return _reject(
            f"prompt sink rejects proof record from source_type={non_evidence_source_type} ref={envelope.ref}"
        )
    if envelope.kind not in checks.evidence_kinds:
        return None
    unsupported_citations = checks.citations_with_prefixes(envelope, checks.disallowed_evidence_citation_prefixes)
    if unsupported_citations:
        return _reject(f"prompt sink rejects non-evidence citation support (including rag citation) ref={envelope.ref}")
    return _source_ref_decision(
        envelope,
        error_prefix="prompt sink rejects",
        known_evidence_refs=known_evidence_refs,
        known_note_refs=None,
        known_rag_refs=None,
    )


def _finding_record_decision(
    envelope: ContextEnvelope,
    known_evidence_refs: Iterable[str] | None,
    checks: PromptSinkChecks,
) -> PromptSinkDecision | None:
    non_finding_source_type = checks.non_evidence_proof_source_type(envelope, frozenset({"finding"}))
    if non_finding_source_type:
        return _reject(
            f"prompt sink rejects proof record from source_type={non_finding_source_type} ref={envelope.ref}"
        )
    if envelope.kind != "finding":
        return None
    return _source_ref_decision(
        envelope,
        error_prefix="prompt sink rejects",
        known_evidence_refs=known_evidence_refs,
        known_note_refs=None,
        known_rag_refs=None,
    )


def _ai_derived_decision(
    envelope: ContextEnvelope,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
    checks: PromptSinkChecks,
) -> PromptSinkDecision | None:
    if envelope.kind not in checks.prompt_ai_derived_kinds:
        return None
    placeholder_citations = placeholder_source_refs(envelope.citations)
    if placeholder_citations:
        return _reject(
            "prompt sink rejects placeholder citations for AI-derived context "
            f"ref={envelope.ref}: {', '.join(placeholder_citations)}"
        )
    return _source_ref_decision(
        envelope,
        error_prefix="prompt sink rejects",
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )


def _source_ref_decision(
    envelope: ContextEnvelope,
    *,
    error_prefix: str,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> PromptSinkDecision | None:
    source_ref_errors = source_refs_metadata_errors(envelope)
    if source_ref_errors:
        return _reject(f"{error_prefix} {source_ref_errors[0]} ref={envelope.ref}")
    unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
        envelope.ref,
        source_refs_metadata_values(envelope),
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )
    if unresolved_source_refs:
        return _reject("; ".join(unresolved_source_refs))
    return None


def _citation_decision(
    envelope: ContextEnvelope,
    known_evidence_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> PromptSinkDecision | None:
    citations = CitationValidator(
        known_evidence_refs=known_evidence_refs,
        known_rag_refs=known_rag_refs,
    ).validate([envelope])
    if not citations.valid:
        return _reject("; ".join(citations.errors))
    return None


def _is_generated_export_material(envelope: ContextEnvelope) -> bool:
    return (
        is_generated_export_context(envelope)
        or has_generated_export_path(envelope)
        or is_generated_export_path(raw_metadata_value(envelope, "source_url"))
    )


def _reject(message: str) -> PromptSinkDecision:
    return PromptSinkDecision("reject", message)
