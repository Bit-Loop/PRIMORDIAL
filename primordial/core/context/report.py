from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from primordial.core.context.bindings import current_context_binding_error
from primordial.core.context.citations import CitationValidator
from primordial.core.context.evidence_shape import (
    EVIDENCE_REF_PREFIX,
    FINDING_REF_PREFIX,
    evidence_shape_omission_reason,
    finding_shape_omission_reason,
)
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.generated_exports import is_generated_export_context
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys
from primordial.core.context.poison import has_context_flag
from primordial.core.context.source_refs import (
    AI_DERIVED_SOURCE_REF_REQUIREMENT,
    has_ai_derived_source_ref,
    unsupported_ai_derived_source_refs,
    unresolved_ai_derived_source_ref_errors,
)
from primordial.core.context.source_types import EVIDENCE_PROOF_KINDS, NON_EVIDENCE_SOURCE_TYPES, TRUTH_LIKE_AUTHORITIES


AI_DERIVED_KINDS = frozenset({"model_summary", "hypothesis", "candidate_task"})
FORBIDDEN_REPORT_SOURCE_TYPES = frozenset({"chat"})
FORBIDDEN_REPORT_FLAGS = (
    "contains_raw_expected_flag",
    "contains_raw_flag",
    "hidden_solution_material",
    "contains_secret",
    "expected_flag_visible",
)


@dataclass(frozen=True, slots=True)
class ReportSinkDecision:
    action: str
    message: str = ""


def validate_report_sink(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None = None,
    known_rag_refs: Iterable[str] | None = None,
) -> ReportSinkDecision:
    if is_generated_export_context(envelope):
        return ReportSinkDecision(
            "reject",
            f"report sink rejects generated export recursion ref={envelope.ref}",
        )
    if envelope.source_type in FORBIDDEN_REPORT_SOURCE_TYPES:
        return ReportSinkDecision("reject", f"report sink rejects raw chat context ref={envelope.ref}")
    if has_context_flag(envelope, FORBIDDEN_REPORT_FLAGS):
        return ReportSinkDecision(
            "reject",
            f"report sink rejects hidden or raw sensitive material ref={envelope.ref}",
        )
    proof_shape_reason = evidence_shape_omission_reason(envelope)
    if proof_shape_reason == "ref":
        return ReportSinkDecision(
            "reject",
            f"report sink requires {EVIDENCE_REF_PREFIX}<id> ref={envelope.ref}",
        )
    if proof_shape_reason:
        return ReportSinkDecision(
            "reject",
            f"report sink rejects evidence {proof_shape_reason} ref={envelope.ref}",
        )
    finding_shape_reason = finding_shape_omission_reason(envelope)
    if finding_shape_reason == "ref":
        return ReportSinkDecision(
            "reject",
            f"report sink requires {FINDING_REF_PREFIX}<id> ref={envelope.ref}",
        )
    if _is_proof_from_non_evidence_source(envelope):
        return ReportSinkDecision(
            "reject",
            f"report sink rejects proof record from source_type={envelope.source_type} ref={envelope.ref}",
        )
    binding_reason = current_context_binding_error(envelope, proof_records=True, target_facts=True)
    if binding_reason:
        return ReportSinkDecision(
            "reject",
            f"report sink rejects {binding_reason} context ref={envelope.ref}",
        )
    if envelope.kind in AI_DERIVED_KINDS and envelope.authority in TRUTH_LIKE_AUTHORITIES:
        return ReportSinkDecision(
            "reject",
            f"report sink rejects truth-like authority on AI-derived context ref={envelope.ref}",
        )
    if envelope.kind in AI_DERIVED_KINDS and not _has_citations(envelope):
        return ReportSinkDecision(
            "reject",
            f"report sink requires citations for AI-derived context ref={envelope.ref}",
        )
    if envelope.kind in AI_DERIVED_KINDS and not has_ai_derived_report_citation(envelope):
        return ReportSinkDecision(
            "reject",
            f"report sink requires {AI_DERIVED_SOURCE_REF_REQUIREMENT} citation for AI-derived context "
            f"ref={envelope.ref}",
        )
    unsupported_citations = unsupported_ai_derived_report_citations(envelope)
    if envelope.kind in AI_DERIVED_KINDS and unsupported_citations:
        refs = ", ".join(unsupported_citations)
        return ReportSinkDecision(
            "reject",
            f"report sink rejects unsupported citations for AI-derived context ref={envelope.ref}: {refs}",
        )
    if envelope.kind in AI_DERIVED_KINDS and _has_malformed_source_refs(envelope):
        return ReportSinkDecision(
            "reject",
            f"report sink rejects malformed source_refs for AI-derived context ref={envelope.ref}",
        )
    unsupported_source_refs = _unsupported_source_refs(envelope)
    if envelope.kind in AI_DERIVED_KINDS and unsupported_source_refs:
        refs = ", ".join(unsupported_source_refs)
        return ReportSinkDecision(
            "reject",
            f"report sink rejects unsupported source_refs for AI-derived context ref={envelope.ref}: {refs}",
        )
    uncited_source_refs = _uncited_source_refs(envelope)
    if envelope.kind in AI_DERIVED_KINDS and uncited_source_refs:
        refs = ", ".join(uncited_source_refs)
        return ReportSinkDecision(
            "reject",
            f"report sink rejects uncited source_refs for AI-derived context ref={envelope.ref}: {refs}",
        )
    unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
        envelope.ref,
        envelope.citations,
        known_evidence_refs=known_evidence_refs,
        known_rag_refs=known_rag_refs,
    )
    if envelope.kind in AI_DERIVED_KINDS and unresolved_source_refs:
        return ReportSinkDecision("reject", "; ".join(unresolved_source_refs))
    citations = CitationValidator(
        known_evidence_refs=known_evidence_refs,
        known_rag_refs=known_rag_refs,
    ).validate([envelope])
    if not citations.valid:
        return ReportSinkDecision("reject", "; ".join(citations.errors))
    return ReportSinkDecision("accept")


def has_ai_derived_report_citation(envelope: ContextEnvelope) -> bool:
    return has_ai_derived_source_ref(envelope.citations)


def unsupported_ai_derived_report_citations(envelope: ContextEnvelope) -> list[str]:
    return unsupported_ai_derived_source_refs(envelope.citations)


def _unsupported_source_refs(envelope: ContextEnvelope) -> list[str]:
    refs = _source_ref_values(envelope)
    if refs is None:
        return []
    return unsupported_ai_derived_source_refs(refs)


def _uncited_source_refs(envelope: ContextEnvelope) -> list[str]:
    refs = _source_ref_values(envelope)
    if refs is None:
        return []
    citations = {str(item).strip() for item in envelope.citations if str(item).strip()}
    return sorted({ref for ref in refs if ref not in citations})


def _source_ref_values(envelope: ContextEnvelope) -> list[str] | None:
    refs = _metadata_value(envelope, "source_refs")
    if refs is None:
        return None
    if isinstance(refs, str):
        values = [refs]
    elif isinstance(refs, list | tuple | set):
        values = list(refs)
    else:
        return []
    return [str(item).strip() for item in values if str(item).strip()]


def _has_malformed_source_refs(envelope: ContextEnvelope) -> bool:
    refs = _metadata_value(envelope, "source_refs")
    return refs is not None and not isinstance(refs, str | list | tuple | set)


def _metadata_value(envelope: ContextEnvelope, *names: str) -> object | None:
    normalized_names = normalized_context_keys(names)
    for raw_key, value in envelope.metadata.items():
        if normalized_context_key(raw_key) in normalized_names:
            return value
    return None


def _has_citations(envelope: ContextEnvelope) -> bool:
    return any(str(citation).strip() for citation in envelope.citations)


def _is_proof_from_non_evidence_source(envelope: ContextEnvelope) -> bool:
    return envelope.kind in EVIDENCE_PROOF_KINDS and envelope.source_type in NON_EVIDENCE_SOURCE_TYPES
