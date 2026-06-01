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
    has_ai_derived_source_ref,
    source_refs_metadata_errors,
    source_refs_metadata_values,
    unresolved_ai_derived_source_ref_errors,
    unsupported_ai_derived_source_refs,
)
from primordial.core.context.source_types import EVIDENCE_PROOF_KINDS, NON_EVIDENCE_SOURCE_TYPES, TRUTH_LIKE_AUTHORITIES
from primordial.core.context.writeup_policy import prompt_writeup_omission_reason


AI_SUMMARY_KINDS = frozenset({"model_summary", "hypothesis", "candidate_task"})
RAG_CITATION_PREFIX = "rag:"
FORBIDDEN_NOTION_EXPORT_SOURCE_TYPES = frozenset({"chat"})
FORBIDDEN_NOTION_EXPORT_FLAGS = (
    "contains_credential",
    "contains_hidden_solution",
    "contains_raw_expected_flag",
    "contains_raw_flag",
    "contains_secret",
    "contains_sensitive_raw_target_evidence",
    "expected_flag_visible",
    "hidden_solution_material",
)


@dataclass(frozen=True, slots=True)
class NotionExportDecision:
    action: str
    message: str = ""


def validate_notion_export_envelope(
    envelope: ContextEnvelope,
    seen_ai_summaries: set[tuple[str, tuple[str, ...]]],
    *,
    known_evidence_refs: Iterable[str] | None = None,
    known_note_refs: Iterable[str] | None = None,
    known_rag_refs: Iterable[str] | None = None,
) -> NotionExportDecision:
    common_decision = _validate_notion_export_common(envelope)
    if common_decision:
        return common_decision
    if envelope.kind == "rag":
        return _validate_notion_export_rag(
            envelope,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
            known_rag_refs=known_rag_refs,
        )
    if envelope.kind == "operator_note":
        source_ref_decision = _validate_notion_export_source_refs(
            envelope,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
            known_rag_refs=known_rag_refs,
        )
        if source_ref_decision:
            return source_ref_decision
    if envelope.kind not in AI_SUMMARY_KINDS:
        return _validate_notion_export_citations(
            envelope,
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        )
    return _validate_notion_export_ai_summary(
        envelope,
        seen_ai_summaries,
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )


def _validate_notion_export_common(envelope: ContextEnvelope) -> NotionExportDecision | None:
    if is_generated_export_context(envelope) or has_generated_export_path(envelope):
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: generated export recursion",
        )
    if _forbidden_notion_export_source_type(envelope):
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: raw chat context",
        )
    if has_context_flag(envelope, FORBIDDEN_NOTION_EXPORT_FLAGS):
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: raw sensitive material",
        )
    note_source_reason = operator_note_source_omission_reason(envelope)
    if note_source_reason:
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: {note_source_reason}",
        )
    writeup_reason = prompt_writeup_omission_reason(envelope, role="report_writer")
    if writeup_reason:
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: {writeup_reason}",
        )
    proof_shape_reason = evidence_shape_omission_reason(envelope)
    if proof_shape_reason == "ref":
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: proof section requires {EVIDENCE_REF_PREFIX}<id> ref",
        )
    if proof_shape_reason:
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: proof section rejects {proof_shape_reason}",
        )
    finding_shape_reason = finding_shape_omission_reason(envelope)
    if finding_shape_reason == "ref":
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: proof section requires {FINDING_REF_PREFIX}<id> ref",
        )
    non_evidence_proof_source_type = _non_evidence_proof_source_type(envelope)
    if non_evidence_proof_source_type:
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: proof section rejects "
            f"source_type={non_evidence_proof_source_type}",
        )
    binding_reason = current_context_binding_error(envelope, proof_records=True, target_facts=True)
    if binding_reason:
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: {binding_reason} context",
        )
    return None


def _validate_notion_export_rag(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> NotionExportDecision:
    if not _has_citation_prefix(envelope, RAG_CITATION_PREFIX):
        return NotionExportDecision("quarantine", f"notion_export quarantines {envelope.ref}: missing rag citation")
    source_ref_decision = _validate_notion_export_source_refs(
        envelope,
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )
    if source_ref_decision:
        return source_ref_decision
    return _validate_notion_export_citations(
        envelope,
        known_evidence_refs=known_evidence_refs,
        known_rag_refs=known_rag_refs,
    )


def _validate_notion_export_citations(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> NotionExportDecision:
    citations = CitationValidator(
        known_evidence_refs=known_evidence_refs,
        known_rag_refs=known_rag_refs,
    ).validate([envelope])
    if not citations.valid:
        return NotionExportDecision("quarantine", "; ".join(citations.errors))
    return NotionExportDecision("accept")


def _validate_notion_export_source_refs(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> NotionExportDecision | None:
    source_ref_decision = _validate_notion_export_source_ref_shape(envelope)
    if source_ref_decision:
        return source_ref_decision
    return _validate_notion_export_unresolved_source_refs(
        envelope,
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )


def _validate_notion_export_source_ref_shape(envelope: ContextEnvelope) -> NotionExportDecision | None:
    source_ref_errors = source_refs_metadata_errors(envelope)
    if not source_ref_errors:
        return None
    return NotionExportDecision(
        "quarantine",
        f"notion_export quarantines {envelope.ref}: {source_ref_errors[0]}",
    )


def _validate_notion_export_unresolved_source_refs(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> NotionExportDecision | None:
    unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
        envelope.ref,
        source_refs_metadata_values(envelope),
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )
    if unresolved_source_refs:
        return NotionExportDecision("quarantine", "; ".join(unresolved_source_refs))
    return None


def _validate_notion_export_ai_summary(
    envelope: ContextEnvelope,
    seen_ai_summaries: set[tuple[str, tuple[str, ...]]],
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> NotionExportDecision:
    if _has_truth_like_authority(envelope):
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: truth-like authority on AI-derived context",
        )
    if not _has_export_citation(envelope):
        return NotionExportDecision("quarantine", f"notion_export quarantines {envelope.ref}: missing citations")
    source_ref_decision = _validate_notion_export_source_ref_shape(envelope)
    if source_ref_decision:
        return source_ref_decision
    unsupported_citations = _unsupported_ai_citations(envelope)
    if unsupported_citations:
        refs = ", ".join(unsupported_citations)
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: unsupported citations {refs}",
        )
    citation_decision = _validate_notion_export_citations(
        envelope,
        known_evidence_refs=known_evidence_refs,
        known_rag_refs=known_rag_refs,
    )
    if citation_decision.action != "accept":
        return citation_decision
    unresolved_decision = _validate_notion_export_unresolved_source_refs(
        envelope,
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )
    if unresolved_decision:
        return unresolved_decision
    summary_key = _ai_summary_dedupe_key(envelope)
    if summary_key in seen_ai_summaries:
        return NotionExportDecision("quarantine", f"notion_export quarantines {envelope.ref}: duplicate AI summary")
    seen_ai_summaries.add(summary_key)
    return NotionExportDecision("accept")


def _has_export_citation(envelope: ContextEnvelope) -> bool:
    return has_ai_derived_source_ref(envelope.citations)


def _ai_summary_dedupe_key(envelope: ContextEnvelope) -> tuple[str, tuple[str, ...]]:
    return (envelope.content_hash, tuple(sorted(_source_refs(envelope))))


def _source_refs(envelope: ContextEnvelope) -> list[str]:
    refs = [str(item).strip() for item in source_refs_metadata_values(envelope) if str(item).strip()]
    if refs:
        return refs
    return list(envelope.citations)


def _unsupported_ai_citations(envelope: ContextEnvelope) -> list[str]:
    return unsupported_ai_derived_source_refs(envelope.citations)


def _forbidden_notion_export_source_type(envelope: ContextEnvelope) -> str:
    source_types = {normalized_context_key(envelope.source_type), *_metadata_text_values(envelope, "source_type")}
    return next(iter(sorted(source_types & FORBIDDEN_NOTION_EXPORT_SOURCE_TYPES)), "")


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


def _has_citation_prefix(envelope: ContextEnvelope, prefix: str) -> bool:
    return any(str(item).startswith(prefix) for item in envelope.citations)


def _non_evidence_proof_source_type(envelope: ContextEnvelope) -> str:
    if envelope.kind not in EVIDENCE_PROOF_KINDS:
        return ""
    source_types = {normalized_context_key(envelope.source_type), *_metadata_text_values(envelope, "source_type")}
    return next(iter(sorted(source_types & NON_EVIDENCE_SOURCE_TYPES)), "")
