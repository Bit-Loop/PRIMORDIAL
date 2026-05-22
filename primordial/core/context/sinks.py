from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from primordial.core.context.authority_refs import unresolved_policy_decision_citation_errors
from primordial.core.context.bindings import current_context_binding_error, has_target_fact_marker
from primordial.core.context.citations import CitationValidator
from primordial.core.context.collaboration import validate_collaboration_sink
from primordial.core.context.ctfd import validate_ctfd_registry_sink, validate_ctfd_submission_sink
from primordial.core.context.evidence_shape import (
    EVIDENCE_AUTHORITIES,
    EVIDENCE_CONTEXT_AUTHORITIES,
    EVIDENCE_REF_PREFIX,
    FINDING_REF_PREFIX,
    evidence_shape_omission_reason,
    finding_shape_omission_reason,
)
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.generated_exports import is_generated_export_context
from primordial.core.context.github_ledger import validate_github_ledger_envelope
from primordial.core.context.normalization import normalized_context_key
from primordial.core.context.notion_export import validate_notion_export_envelope
from primordial.core.context.notion_inbox import validate_notion_inbox_envelope
from primordial.core.context.purposes import OPERATIONAL_CONTEXT_PURPOSES
from primordial.core.context.rag_index import validate_rag_index_sink
from primordial.core.context.report import validate_report_sink
from primordial.core.context.source_refs import (
    source_refs_metadata_errors,
    source_refs_metadata_values,
    unresolved_ai_derived_source_ref_errors,
)
from primordial.core.context.source_types import NON_EVIDENCE_SOURCE_TYPES, RAG_ADVISORY_SOURCE_TYPES
from primordial.core.context.task_metadata import task_metadata_errors


EVIDENCE_KINDS = frozenset({"evidence"})
DISALLOWED_EVIDENCE_SOURCE_TYPES = NON_EVIDENCE_SOURCE_TYPES
DISALLOWED_EVIDENCE_CITATION_PREFIXES = ("rag:", "model:", "github:", "notion:", "ctfd:", "chat:")
DISALLOWED_FINDING_SOURCE_TYPES = DISALLOWED_EVIDENCE_SOURCE_TYPES
TASK_METADATA_KINDS = frozenset({"task", "candidate_task", "task_metadata"})
PROMPT_RAW_CHAT_SOURCE_TYPES = frozenset({"chat"})
PROMPT_AI_DERIVED_KINDS = frozenset({"model_summary", "hypothesis", "candidate_task"})


@dataclass(slots=True)
class ContextSinkValidationResult:
    valid: bool
    accepted_refs: list[str] = field(default_factory=list)
    rejected_refs: list[str] = field(default_factory=list)
    quarantined_refs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_payload(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "accepted_refs": list(self.accepted_refs),
            "rejected_refs": list(self.rejected_refs),
            "quarantined_refs": list(self.quarantined_refs),
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


class ContextSinkValidator:
    def validate(
        self,
        sink: str,
        envelopes: Iterable[ContextEnvelope],
        *,
        known_evidence_refs: Iterable[str] | None = None,
        known_policy_decision_refs: Iterable[str] | None = None,
        known_rag_refs: Iterable[str] | None = None,
    ) -> ContextSinkValidationResult:
        normalized_sink = normalized_context_key(sink)
        result = ContextSinkValidationResult(valid=True)
        notion_export_ai_summaries: set[tuple[str, tuple[str, ...]]] = set()
        for envelope in envelopes:
            if self._has_sink_mismatch(normalized_sink, envelope):
                self._reject(
                    result,
                    envelope,
                    f"sink mismatch ref={envelope.ref} envelope.sink={envelope.sink or '<empty>'} "
                    f"requested={normalized_sink or '<empty>'}",
                )
                continue
            if normalized_sink == "evidence":
                self._validate_evidence_sink(
                    envelope,
                    result,
                    known_evidence_refs=known_evidence_refs,
                )
            elif normalized_sink == "prompt":
                self._validate_prompt_sink(
                    envelope,
                    result,
                    known_evidence_refs=known_evidence_refs,
                    known_rag_refs=known_rag_refs,
                )
            elif normalized_sink == "finding":
                self._validate_finding_sink(
                    envelope,
                    result,
                    known_evidence_refs=known_evidence_refs,
                    known_rag_refs=known_rag_refs,
                )
            elif normalized_sink == "task_metadata":
                self._validate_task_metadata_sink(
                    envelope,
                    result,
                    known_evidence_refs=known_evidence_refs,
                    known_policy_decision_refs=known_policy_decision_refs,
                    known_rag_refs=known_rag_refs,
                )
            elif normalized_sink == "notion_export":
                self._validate_notion_export_sink(
                    envelope,
                    result,
                    notion_export_ai_summaries,
                    known_evidence_refs=known_evidence_refs,
                    known_rag_refs=known_rag_refs,
                )
            elif normalized_sink == "notion_inbox":
                self._validate_notion_inbox_sink(envelope, result)
            elif normalized_sink == "rag_index":
                self._validate_rag_index_sink(envelope, result, known_rag_refs=known_rag_refs)
            elif normalized_sink in {"discord_notification", "github_issue"}:
                self._validate_collaboration_sink(
                    normalized_sink,
                    envelope,
                    result,
                    known_evidence_refs=known_evidence_refs,
                    known_rag_refs=known_rag_refs,
                )
            elif normalized_sink == "github_ledger":
                self._validate_github_ledger_sink(envelope, result)
            elif normalized_sink == "ctfd_registry":
                self._validate_ctfd_registry_sink(envelope, result)
            elif normalized_sink == "ctfd_submission":
                self._validate_ctfd_submission_sink(envelope, result)
            elif normalized_sink == "report":
                self._validate_report_sink(
                    envelope,
                    result,
                    known_evidence_refs=known_evidence_refs,
                    known_rag_refs=known_rag_refs,
                )
            else:
                if (
                    normalized_sink in OPERATIONAL_CONTEXT_PURPOSES
                    or normalized_context_key(envelope.purpose) in OPERATIONAL_CONTEXT_PURPOSES
                ):
                    self._reject(
                        result,
                        envelope,
                        f"unknown operational sink {normalized_sink or '<empty>'} ref={envelope.ref}",
                    )
                    continue
                result.accepted_refs.append(envelope.ref)
                result.warnings.append(f"no specialized sink rules for {normalized_sink or '<empty>'}")
        result.accepted_refs = sorted(set(result.accepted_refs))
        result.rejected_refs = sorted(set(result.rejected_refs))
        result.quarantined_refs = sorted(set(result.quarantined_refs))
        result.valid = not result.errors
        return result

    def _has_sink_mismatch(self, normalized_sink: str, envelope: ContextEnvelope) -> bool:
        return normalized_context_key(envelope.sink) != normalized_sink

    def _validate_evidence_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        *,
        known_evidence_refs: Iterable[str] | None,
    ) -> None:
        if envelope.kind not in EVIDENCE_KINDS:
            self._reject(result, envelope, f"evidence sink rejects kind={envelope.kind} ref={envelope.ref}")
            return
        if envelope.authority not in EVIDENCE_AUTHORITIES:
            self._reject(result, envelope, f"evidence sink rejects authority={envelope.authority} ref={envelope.ref}")
            return
        if not envelope.ref.startswith(EVIDENCE_REF_PREFIX):
            self._reject(result, envelope, f"evidence sink requires evidence:<id> ref, got {envelope.ref}")
            return
        if envelope.source_type in DISALLOWED_EVIDENCE_SOURCE_TYPES:
            self._reject(
                result,
                envelope,
                f"evidence sink rejects source_type={envelope.source_type} ref={envelope.ref}",
            )
            return
        unsupported_citations = _citations_with_prefixes(envelope, DISALLOWED_EVIDENCE_CITATION_PREFIXES)
        if unsupported_citations:
            self._reject(
                result,
                envelope,
                "evidence sink rejects non-evidence citation support "
                f"(including rag citation) ref={envelope.ref}",
            )
            return
        unresolved_citations = _unresolved_evidence_citations(envelope, known_evidence_refs)
        if unresolved_citations:
            self._reject(
                result,
                envelope,
                "evidence sink rejects unresolved evidence citation(s) "
                f"ref={envelope.ref}: {', '.join(unresolved_citations)}",
            )
            return
        binding_reason = current_context_binding_error(envelope, proof_records=True)
        if binding_reason:
            self._reject(result, envelope, f"evidence sink rejects {binding_reason} context ref={envelope.ref}")
            return
        result.accepted_refs.append(envelope.ref)

    def _validate_finding_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        *,
        known_evidence_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        if envelope.kind != "finding":
            self._reject(result, envelope, f"finding sink rejects kind={envelope.kind} ref={envelope.ref}")
            return
        if not envelope.ref.startswith(FINDING_REF_PREFIX):
            self._reject(result, envelope, f"finding sink requires {FINDING_REF_PREFIX}<id> ref, got {envelope.ref}")
            return
        citations = CitationValidator(
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        ).validate([envelope])
        if not citations.valid:
            self._reject(result, envelope, "; ".join(citations.errors))
            return
        if envelope.source_type in DISALLOWED_FINDING_SOURCE_TYPES:
            self._reject(result, envelope, f"finding sink rejects source_type={envelope.source_type} ref={envelope.ref}")
            return
        binding_reason = current_context_binding_error(envelope, proof_records=True)
        if binding_reason:
            self._reject(result, envelope, f"finding sink rejects {binding_reason} context ref={envelope.ref}")
            return
        result.accepted_refs.append(envelope.ref)

    def _validate_prompt_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        *,
        known_evidence_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        evidence_shape_reason = evidence_shape_omission_reason(
            envelope,
            allowed_authorities=EVIDENCE_CONTEXT_AUTHORITIES,
        )
        if evidence_shape_reason == "ref":
            self._reject(result, envelope, f"prompt sink requires {EVIDENCE_REF_PREFIX}<id> ref, got {envelope.ref}")
            return
        if evidence_shape_reason:
            self._reject(result, envelope, f"prompt sink rejects evidence {evidence_shape_reason} ref={envelope.ref}")
            return
        finding_shape_reason = finding_shape_omission_reason(envelope)
        if finding_shape_reason == "ref":
            self._reject(result, envelope, f"prompt sink requires {FINDING_REF_PREFIX}<id> ref, got {envelope.ref}")
            return
        if envelope.kind == "rag" and has_target_fact_marker(envelope):
            self._reject(result, envelope, f"prompt sink rejects target fact rag ref={envelope.ref}")
            return
        binding_reason = current_context_binding_error(envelope, proof_records=True, target_facts=True)
        if binding_reason:
            self._reject(result, envelope, f"prompt sink rejects {binding_reason} context ref={envelope.ref}")
            return
        if is_generated_export_context(envelope):
            self._reject(result, envelope, f"prompt sink rejects generated_export ref={envelope.ref}")
            return
        if envelope.source_type in PROMPT_RAW_CHAT_SOURCE_TYPES:
            self._reject(result, envelope, f"prompt sink rejects raw_chat_context ref={envelope.ref}")
            return
        if envelope.kind == "rag" and envelope.source_type not in RAG_ADVISORY_SOURCE_TYPES:
            self._reject(
                result,
                envelope,
                f"prompt sink rejects non_advisory_rag_source source_type={envelope.source_type} ref={envelope.ref}",
            )
            return
        if envelope.kind in EVIDENCE_KINDS and envelope.source_type in DISALLOWED_EVIDENCE_SOURCE_TYPES:
            self._reject(
                result,
                envelope,
                f"prompt sink rejects proof record from source_type={envelope.source_type} ref={envelope.ref}",
            )
            return
        if envelope.kind == "finding" and envelope.source_type in DISALLOWED_FINDING_SOURCE_TYPES:
            self._reject(
                result,
                envelope,
                f"prompt sink rejects proof record from source_type={envelope.source_type} ref={envelope.ref}",
            )
            return
        if envelope.kind in PROMPT_AI_DERIVED_KINDS:
            source_ref_errors = source_refs_metadata_errors(envelope)
            if source_ref_errors:
                self._reject(
                    result,
                    envelope,
                    f"prompt sink rejects {source_ref_errors[0]} ref={envelope.ref}",
                )
                return
            unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
                envelope.ref,
                source_refs_metadata_values(envelope),
                known_evidence_refs=known_evidence_refs,
                known_rag_refs=known_rag_refs,
            )
            if unresolved_source_refs:
                self._reject(result, envelope, "; ".join(unresolved_source_refs))
                return
        citations = CitationValidator(
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        ).validate([envelope])
        if not citations.valid:
            self._reject(result, envelope, "; ".join(citations.errors))
            return
        result.accepted_refs.append(envelope.ref)

    def _validate_task_metadata_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        *,
        known_evidence_refs: Iterable[str] | None,
        known_policy_decision_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        if envelope.kind not in TASK_METADATA_KINDS:
            self._reject(result, envelope, f"task_metadata sink rejects kind={envelope.kind} ref={envelope.ref}")
            return
        citations = CitationValidator(
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        ).validate([envelope])
        errors = task_metadata_errors(envelope, known_evidence_refs=known_evidence_refs)
        errors.extend(
            unresolved_policy_decision_citation_errors(
                envelope,
                known_policy_decision_refs=known_policy_decision_refs,
            )
        )
        if not citations.valid or errors:
            result.rejected_refs.append(envelope.ref)
            result.errors.extend(citations.errors)
            result.errors.extend(errors)
            return
        result.accepted_refs.append(envelope.ref)

    def _validate_notion_export_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        seen_ai_summaries: set[tuple[str, tuple[str, ...]]],
        *,
        known_evidence_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        decision = validate_notion_export_envelope(
            envelope,
            seen_ai_summaries,
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        )
        if decision.action == "accept":
            result.accepted_refs.append(envelope.ref)
            return
        result.quarantined_refs.append(envelope.ref)
        result.errors.append(decision.message)

    def _validate_notion_inbox_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
    ) -> None:
        decision = validate_notion_inbox_envelope(envelope)
        if decision.action == "accept":
            result.accepted_refs.append(envelope.ref)
            return
        if decision.action == "quarantine":
            result.quarantined_refs.append(envelope.ref)
            result.errors.append(decision.message)
            return
        self._reject(result, envelope, decision.message)

    def _validate_rag_index_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        *,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        decision = validate_rag_index_sink(envelope, known_rag_refs=known_rag_refs)
        if decision.action == "accept":
            result.accepted_refs.append(envelope.ref)
            return
        self._reject(result, envelope, decision.message)

    def _validate_collaboration_sink(
        self,
        sink: str,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        *,
        known_evidence_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        decision = validate_collaboration_sink(
            sink,
            envelope,
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        )
        if decision.action == "accept":
            result.accepted_refs.append(envelope.ref)
            return
        if decision.action == "reject":
            self._reject(result, envelope, decision.message)
            return
        if decision.action == "quarantine":
            result.quarantined_refs.append(envelope.ref)
            result.errors.append(decision.message)

    def _validate_github_ledger_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
    ) -> None:
        decision = validate_github_ledger_envelope(envelope)
        if decision.action == "accept":
            result.accepted_refs.append(envelope.ref)
            return
        self._reject(result, envelope, decision.message)

    def _validate_ctfd_submission_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
    ) -> None:
        decision = validate_ctfd_submission_sink(envelope)
        if decision.action == "accept":
            result.accepted_refs.append(envelope.ref)
            return
        self._reject(result, envelope, decision.message)

    def _validate_ctfd_registry_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
    ) -> None:
        decision = validate_ctfd_registry_sink(envelope)
        if decision.action == "accept":
            result.accepted_refs.append(envelope.ref)
            return
        self._reject(result, envelope, decision.message)

    def _validate_report_sink(
        self,
        envelope: ContextEnvelope,
        result: ContextSinkValidationResult,
        *,
        known_evidence_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        decision = validate_report_sink(
            envelope,
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        )
        if decision.action == "accept":
            result.accepted_refs.append(envelope.ref)
            return
        self._reject(result, envelope, decision.message)

    def _reject(
        self,
        result: ContextSinkValidationResult,
        envelope: ContextEnvelope,
        message: str,
    ) -> None:
        result.rejected_refs.append(envelope.ref)
        result.errors.append(message)


def _citations_with_prefixes(envelope: ContextEnvelope, prefixes: Iterable[str]) -> list[str]:
    normalized_prefixes = tuple(prefix.lower() for prefix in prefixes)
    return [
        citation
        for citation in (str(citation).strip() for citation in envelope.citations)
        if citation.lower().startswith(normalized_prefixes)
    ]


def _unresolved_evidence_citations(
    envelope: ContextEnvelope,
    known_evidence_refs: Iterable[str] | None,
) -> list[str]:
    if known_evidence_refs is None:
        return []
    known_refs = {str(ref).strip() for ref in known_evidence_refs if str(ref).strip()}
    known_refs.add(envelope.ref)
    citations = _citations_with_prefixes(envelope, (EVIDENCE_REF_PREFIX,))
    return sorted(set(citations) - known_refs)
