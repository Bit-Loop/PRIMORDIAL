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
from primordial.core.context.generated_exports import has_generated_export_path, is_generated_export_context
from primordial.core.context.normalization import normalized_context_key
from primordial.core.context.operator_notes import operator_note_source_omission_reason
from primordial.core.context.poison import has_context_flag
from primordial.core.context.source_refs import (
    AI_DERIVED_SOURCE_REF_REQUIREMENT,
    has_ai_derived_source_ref,
    placeholder_source_refs,
    source_refs_metadata_errors,
    source_refs_metadata_values,
    unsupported_ai_derived_source_refs,
    unresolved_ai_derived_source_ref_errors,
)
from primordial.core.context.source_types import EVIDENCE_PROOF_KINDS, NON_EVIDENCE_SOURCE_TYPES, TRUTH_LIKE_AUTHORITIES
from primordial.core.context.writeup_policy import prompt_writeup_omission_reason


AI_DERIVED_KINDS = frozenset({"model_summary", "hypothesis", "candidate_task"})
SOURCE_REF_VALIDATED_KINDS = AI_DERIVED_KINDS | {"operator_note", "rag"}
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
    known_note_refs: Iterable[str] | None = None,
    known_rag_refs: Iterable[str] | None = None,
) -> ReportSinkDecision:
    for decision in (
        _report_context_material_decision(envelope),
        _report_proof_shape_decision(envelope),
        _report_ai_derived_decision(envelope),
        _report_source_refs_decision(
            envelope,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
            known_rag_refs=known_rag_refs,
        ),
        _report_citation_decision(
            envelope,
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        ),
    ):
        if decision is not None:
            return decision
    return ReportSinkDecision("accept")


def _report_context_material_decision(envelope: ContextEnvelope) -> ReportSinkDecision | None:
    if is_generated_export_context(envelope) or has_generated_export_path(envelope):
        return ReportSinkDecision(
            "reject",
            f"report sink rejects generated export recursion ref={envelope.ref}",
        )
    if _forbidden_report_source_type(envelope):
        return ReportSinkDecision("reject", f"report sink rejects raw chat context ref={envelope.ref}")
    if has_context_flag(envelope, FORBIDDEN_REPORT_FLAGS):
        return ReportSinkDecision(
            "reject",
            f"report sink rejects hidden or raw sensitive material ref={envelope.ref}",
        )
    note_source_reason = operator_note_source_omission_reason(envelope)
    if note_source_reason:
        return ReportSinkDecision(
            "reject",
            f"report sink rejects {note_source_reason} ref={envelope.ref}",
        )
    writeup_reason = prompt_writeup_omission_reason(envelope, role="report_writer")
    if writeup_reason:
        return ReportSinkDecision(
            "reject",
            f"report sink rejects {writeup_reason} ref={envelope.ref}",
        )
    return None


def _report_proof_shape_decision(envelope: ContextEnvelope) -> ReportSinkDecision | None:
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
    non_evidence_proof_source_type = _non_evidence_proof_source_type(envelope)
    if non_evidence_proof_source_type:
        return ReportSinkDecision(
            "reject",
            f"report sink rejects proof record from source_type={non_evidence_proof_source_type} ref={envelope.ref}",
        )
    binding_reason = current_context_binding_error(envelope, proof_records=True, target_facts=True)
    if binding_reason:
        return ReportSinkDecision(
            "reject",
            f"report sink rejects {binding_reason} context ref={envelope.ref}",
        )
    return None


def _report_ai_derived_decision(envelope: ContextEnvelope) -> ReportSinkDecision | None:
    if envelope.kind not in AI_DERIVED_KINDS:
        return None
    if envelope.kind in AI_DERIVED_KINDS and _has_truth_like_authority(envelope):
        return ReportSinkDecision(
            "reject",
            f"report sink rejects truth-like authority on AI-derived context ref={envelope.ref}",
        )
    if envelope.kind in AI_DERIVED_KINDS and not _has_citations(envelope):
        return ReportSinkDecision(
            "reject",
            f"report sink requires citations for AI-derived context ref={envelope.ref}",
        )
    placeholder_citations = placeholder_source_refs(envelope.citations)
    if envelope.kind in AI_DERIVED_KINDS and placeholder_citations:
        refs = ", ".join(placeholder_citations)
        return ReportSinkDecision(
            "reject",
            f"report sink rejects placeholder citations for AI-derived context ref={envelope.ref}: {refs}",
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
    return None


def _report_source_refs_decision(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> ReportSinkDecision | None:
    if envelope.kind not in SOURCE_REF_VALIDATED_KINDS:
        return None
    source_ref_errors = source_refs_metadata_errors(envelope)
    if envelope.kind in SOURCE_REF_VALIDATED_KINDS and source_ref_errors:
        return ReportSinkDecision(
            "reject",
            f"report sink rejects {source_ref_errors[0]} for source-ref validated context ref={envelope.ref}",
        )
    unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
        envelope.ref,
        source_refs_metadata_values(envelope),
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )
    if envelope.kind in SOURCE_REF_VALIDATED_KINDS and unresolved_source_refs:
        return ReportSinkDecision("reject", "; ".join(unresolved_source_refs))
    return None


def _report_citation_decision(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> ReportSinkDecision | None:
    citations = CitationValidator(
        known_evidence_refs=known_evidence_refs,
        known_rag_refs=known_rag_refs,
    ).validate([envelope])
    if not citations.valid:
        return ReportSinkDecision("reject", "; ".join(citations.errors))
    return None


def has_ai_derived_report_citation(envelope: ContextEnvelope) -> bool:
    return has_ai_derived_source_ref(envelope.citations)


def unsupported_ai_derived_report_citations(envelope: ContextEnvelope) -> list[str]:
    return unsupported_ai_derived_source_refs(envelope.citations)


def _forbidden_report_source_type(envelope: ContextEnvelope) -> str:
    source_types = {normalized_context_key(envelope.source_type), *_metadata_text_values(envelope, "source_type")}
    return next(iter(sorted(source_types & FORBIDDEN_REPORT_SOURCE_TYPES)), "")


def _has_truth_like_authority(envelope: ContextEnvelope) -> bool:
    return normalized_context_key(envelope.authority) in TRUTH_LIKE_AUTHORITIES or bool(
        _metadata_text_values(envelope, "authority", "authorities") & TRUTH_LIKE_AUTHORITIES
    )


def _metadata_text_values(envelope: ContextEnvelope, *names: str) -> set[str]:
    values: set[str] = set()
    for value in _metadata_values_from(envelope.metadata, *names):
        for item in _metadata_scalar_values(value):
            text = normalized_context_key(item)
            if text:
                values.add(text)
    return values


def _metadata_values_from(value: object, *names: str) -> list[object]:
    normalized_names = {normalized_context_key(name) for name in names}
    if "source_type" in normalized_names:
        normalized_names.add("source_types")
    values: list[object] = []
    if isinstance(value, dict):
        items = value.items()
    elif isinstance(value, list | tuple | set):
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
    if isinstance(value, list | tuple | set):
        values: list[object] = []
        for item in value:
            values.extend(_metadata_scalar_values(item))
        return values
    return [value]


def _has_citations(envelope: ContextEnvelope) -> bool:
    return any(str(citation).strip() for citation in envelope.citations)


def _non_evidence_proof_source_type(envelope: ContextEnvelope) -> str:
    if envelope.kind not in EVIDENCE_PROOF_KINDS:
        return ""
    source_types = {normalized_context_key(envelope.source_type), *_metadata_text_values(envelope, "source_type")}
    return next(iter(sorted(source_types & NON_EVIDENCE_SOURCE_TYPES)), "")
