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
    has_ai_derived_source_ref,
    unresolved_ai_derived_source_ref_errors,
    unsupported_ai_derived_source_refs,
)
from primordial.core.context.source_types import EVIDENCE_PROOF_KINDS, NON_EVIDENCE_SOURCE_TYPES, TRUTH_LIKE_AUTHORITIES


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
    known_rag_refs: Iterable[str] | None = None,
) -> NotionExportDecision:
    if is_generated_export_context(envelope):
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: generated export recursion",
        )
    if envelope.source_type in FORBIDDEN_NOTION_EXPORT_SOURCE_TYPES:
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: raw chat context",
        )
    if has_context_flag(envelope, FORBIDDEN_NOTION_EXPORT_FLAGS):
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: raw sensitive material",
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
    if _is_proof_from_non_evidence_source(envelope):
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: proof section rejects "
            f"source_type={envelope.source_type}",
        )
    binding_reason = current_context_binding_error(envelope, proof_records=True, target_facts=True)
    if binding_reason:
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: {binding_reason} context",
        )
    if envelope.kind == "rag":
        if not _has_citation_prefix(envelope, RAG_CITATION_PREFIX):
            return NotionExportDecision("quarantine", f"notion_export quarantines {envelope.ref}: missing rag citation")
        citations = CitationValidator(
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        ).validate([envelope])
        if not citations.valid:
            return NotionExportDecision("quarantine", "; ".join(citations.errors))
        return NotionExportDecision("accept")
    if envelope.kind not in AI_SUMMARY_KINDS:
        citations = CitationValidator(
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        ).validate([envelope])
        if not citations.valid:
            return NotionExportDecision("quarantine", "; ".join(citations.errors))
        return NotionExportDecision("accept")
    if envelope.authority in TRUTH_LIKE_AUTHORITIES:
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: truth-like authority on AI-derived context",
        )
    if not _has_export_citation(envelope):
        return NotionExportDecision("quarantine", f"notion_export quarantines {envelope.ref}: missing citations")
    if _has_malformed_source_refs(envelope):
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: malformed source_refs",
        )
    unsupported_source_refs = _unsupported_source_refs(envelope)
    if unsupported_source_refs:
        refs = ", ".join(unsupported_source_refs)
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: unsupported source_refs {refs}",
        )
    uncited_source_refs = _uncited_source_refs(envelope)
    if uncited_source_refs:
        refs = ", ".join(uncited_source_refs)
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: uncited source_refs {refs}",
        )
    unsupported_citations = _unsupported_ai_citations(envelope)
    if unsupported_citations:
        refs = ", ".join(unsupported_citations)
        return NotionExportDecision(
            "quarantine",
            f"notion_export quarantines {envelope.ref}: unsupported citations {refs}",
        )
    unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
        envelope.ref,
        envelope.citations,
        known_evidence_refs=known_evidence_refs,
        known_rag_refs=known_rag_refs,
    )
    if unresolved_source_refs:
        return NotionExportDecision("quarantine", "; ".join(unresolved_source_refs))
    citations = CitationValidator(
        known_evidence_refs=known_evidence_refs,
        known_rag_refs=known_rag_refs,
    ).validate([envelope])
    if not citations.valid:
        return NotionExportDecision("quarantine", "; ".join(citations.errors))
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
    refs = _source_ref_values(envelope)
    if refs is not None:
        return refs
    return list(envelope.citations)


def _uncited_source_refs(envelope: ContextEnvelope) -> list[str]:
    refs = _source_ref_values(envelope)
    if refs is None:
        return []
    citations = {str(item).strip() for item in envelope.citations if str(item).strip()}
    return sorted({ref for ref in refs if ref not in citations})


def _unsupported_source_refs(envelope: ContextEnvelope) -> list[str]:
    refs = _source_ref_values(envelope)
    if refs is None:
        return []
    return unsupported_ai_derived_source_refs(refs)


def _unsupported_ai_citations(envelope: ContextEnvelope) -> list[str]:
    return unsupported_ai_derived_source_refs(envelope.citations)


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


def _has_citation_prefix(envelope: ContextEnvelope, prefix: str) -> bool:
    return any(str(item).startswith(prefix) for item in envelope.citations)


def _is_proof_from_non_evidence_source(envelope: ContextEnvelope) -> bool:
    return envelope.kind in EVIDENCE_PROOF_KINDS and envelope.source_type in NON_EVIDENCE_SOURCE_TYPES
