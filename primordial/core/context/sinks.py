from __future__ import annotations

from typing import Iterable

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.evidence_shape import EVIDENCE_CONTEXT_AUTHORITIES
from primordial.core.context.normalization import normalized_context_key
from primordial.core.context.sink_dispatch import validate_sink_envelopes
from primordial.core.context.sink_helpers import (
    citations_with_prefixes,
    non_advisory_rag_source_type,
    non_evidence_proof_source_type,
    reject_sink_envelope,
    sink_context_restriction_reject_reason,
)
from primordial.core.context.sink_source_refs import context_known_source_refs
from primordial.core.context.sink_types import (
    DISALLOWED_EVIDENCE_CITATION_PREFIXES,
    DISALLOWED_EVIDENCE_SOURCE_TYPES,
    DISALLOWED_FINDING_CITATION_PREFIXES,
    DISALLOWED_FINDING_SOURCE_TYPES,
    EVIDENCE_KINDS,
    PROMPT_AI_DERIVED_KINDS,
    PROMPT_RAW_CHAT_SOURCE_TYPES,
    TASK_METADATA_KINDS,
    ContextSinkValidationResult,
)
from primordial.core.context.sink_validators import (
    validate_collaboration_sink_payload,
    validate_ctfd_registry_sink_payload,
    validate_ctfd_submission_sink_payload,
    validate_evidence_sink,
    validate_finding_sink,
    validate_github_ledger_sink_payload,
    validate_notion_export_sink_payload,
    validate_notion_inbox_sink_payload,
    validate_prompt_sink_payload,
    validate_rag_index_sink_payload,
    validate_report_sink_payload,
    validate_task_metadata_sink,
)


class ContextSinkValidator:
    def validate(
        self,
        sink: str,
        envelopes: Iterable[ContextEnvelope],
        *,
        known_evidence_refs: Iterable[str] | None = None,
        known_note_refs: Iterable[str] | None = None,
        known_policy_decision_refs: Iterable[str] | None = None,
        known_rag_refs: Iterable[str] | None = None,
    ) -> ContextSinkValidationResult:
        normalized_sink = normalized_context_key(sink)
        return validate_sink_envelopes(
            self,
            normalized_sink=normalized_sink,
            envelopes=list(envelopes),
            result=ContextSinkValidationResult(valid=True),
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
            known_policy_decision_refs=known_policy_decision_refs,
            known_rag_refs=known_rag_refs,
        )

    def _has_sink_mismatch(self, normalized_sink: str, envelope: ContextEnvelope) -> bool:
        return normalized_context_key(envelope.sink) != normalized_sink

    def _context_known_source_refs(
        self,
        envelopes: Iterable[ContextEnvelope],
        *,
        known_evidence_refs: Iterable[str] | None,
        known_note_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> tuple[set[str] | None, set[str], set[str]]:
        return context_known_source_refs(
            envelopes,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
            known_rag_refs=known_rag_refs,
            evidence_kinds=EVIDENCE_KINDS,
            evidence_context_authorities=EVIDENCE_CONTEXT_AUTHORITIES,
            disallowed_evidence_citation_prefixes=DISALLOWED_EVIDENCE_CITATION_PREFIXES,
            citations_with_prefixes=citations_with_prefixes,
            non_evidence_proof_source_type=non_evidence_proof_source_type,
            non_advisory_rag_source_type=non_advisory_rag_source_type,
        )

    def _validate_evidence_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        *,
        known_evidence_refs: Iterable[str] | None,
    ) -> None:
        validate_evidence_sink(envelope, result, known_evidence_refs=known_evidence_refs)

    def _validate_finding_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        *,
        known_evidence_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        validate_finding_sink(
            envelope,
            result,
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        )

    def _validate_prompt_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        *,
        known_evidence_refs: Iterable[str] | None,
        known_note_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        validate_prompt_sink_payload(
            envelope,
            result,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
            known_rag_refs=known_rag_refs,
        )

    def _validate_task_metadata_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        *,
        known_evidence_refs: Iterable[str] | None,
        known_policy_decision_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        validate_task_metadata_sink(
            envelope,
            result,
            known_evidence_refs=known_evidence_refs,
            known_policy_decision_refs=known_policy_decision_refs,
            known_rag_refs=known_rag_refs,
        )

    def _validate_notion_export_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        seen_ai_summaries: set[tuple[str, tuple[str, ...]]],
        *,
        known_evidence_refs: Iterable[str] | None,
        known_note_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        validate_notion_export_sink_payload(
            envelope,
            result,
            seen_ai_summaries,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
            known_rag_refs=known_rag_refs,
        )

    def _validate_notion_inbox_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
    ) -> None:
        validate_notion_inbox_sink_payload(envelope, result)

    def _validate_rag_index_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        *,
        known_evidence_refs: Iterable[str] | None,
        known_note_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        validate_rag_index_sink_payload(
            envelope,
            result,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
            known_rag_refs=known_rag_refs,
        )

    def _validate_collaboration_sink(
        self,
        sink: str,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        *,
        known_evidence_refs: Iterable[str] | None,
        known_note_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        validate_collaboration_sink_payload(
            sink,
            envelope,
            result,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
            known_rag_refs=known_rag_refs,
        )

    def _validate_github_ledger_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
    ) -> None:
        validate_github_ledger_sink_payload(envelope, result)

    def _validate_ctfd_submission_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
    ) -> None:
        validate_ctfd_submission_sink_payload(envelope, result)

    def _validate_ctfd_registry_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
    ) -> None:
        validate_ctfd_registry_sink_payload(envelope, result)

    def _validate_report_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        *,
        known_evidence_refs: Iterable[str] | None,
        known_note_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        validate_report_sink_payload(
            envelope,
            result,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
            known_rag_refs=known_rag_refs,
        )

    def _reject(
        self,
        result: ContextSinkValidationResult,
        envelope: ContextEnvelope,
        message: str,
    ) -> None:
        reject_sink_envelope(result, envelope, message)


_citations_with_prefixes = citations_with_prefixes
_non_evidence_proof_source_type = non_evidence_proof_source_type
_non_advisory_rag_source_type = non_advisory_rag_source_type
_sink_context_restriction_reject_reason = sink_context_restriction_reject_reason
