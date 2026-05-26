from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from primordial.core.context.authority_refs import unresolved_policy_decision_citation_errors
from primordial.core.context.bindings import current_context_binding_error, has_target_fact_marker
from primordial.core.context.citations import CitationValidator
from primordial.core.context.collaboration import validate_collaboration_sink
from primordial.core.context.ctfd import validate_ctfd_registry_sink, validate_ctfd_submission_sink
from primordial.core.context.current_refs import operator_note_source_omission_reason
from primordial.core.context.evidence_shape import (
    EVIDENCE_AUTHORITIES,
    EVIDENCE_CONTEXT_AUTHORITIES,
    EVIDENCE_REF_PREFIX,
    FINDING_REF_PREFIX,
    evidence_shape_omission_reason,
    finding_shape_omission_reason,
)
from primordial.core.context.envelopes import (
    RAG_CHUNK_FORMAT_SOURCE_TYPES,
    RAG_CHUNK_VULN_INTEL_SOURCE_TYPES,
    ContextEnvelope,
)
from primordial.core.context.generated_exports import (
    has_generated_export_path,
    is_generated_export_context,
    is_generated_export_path,
)
from primordial.core.context.github_ledger import validate_github_ledger_envelope
from primordial.core.context.metadata_flags import metadata_value_is_false, raw_metadata_value
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys
from primordial.core.context.notion_export import validate_notion_export_envelope
from primordial.core.context.notion_inbox import validate_notion_inbox_envelope
from primordial.core.context.purposes import OPERATIONAL_CONTEXT_PURPOSES
from primordial.core.context.rag_index import validate_rag_index_sink
from primordial.core.context.report import validate_report_sink
from primordial.core.context.source_refs import (
    canonical_source_ref,
    placeholder_source_refs,
    source_refs_metadata_errors,
    source_refs_metadata_values,
    unresolved_ai_derived_source_ref_errors,
)
from primordial.core.context.source_types import NON_EVIDENCE_SOURCE_TYPES, RAG_ADVISORY_SOURCE_TYPES
from primordial.core.context.task_metadata import task_metadata_errors
from primordial.core.context.writeup_policy import prompt_writeup_omission_reason


EVIDENCE_KINDS = frozenset({"evidence"})
DISALLOWED_EVIDENCE_SOURCE_TYPES = NON_EVIDENCE_SOURCE_TYPES
DISALLOWED_EVIDENCE_CITATION_PREFIXES = ("rag:", "note:", "model:", "github:", "notion:", "ctfd:", "chat:")
DISALLOWED_FINDING_SOURCE_TYPES = DISALLOWED_EVIDENCE_SOURCE_TYPES
DISALLOWED_FINDING_CITATION_PREFIXES = ("rag:", "note:", "model:", "github:", "notion:", "ctfd:", "chat:")
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
        known_note_refs: Iterable[str] | None = None,
        known_policy_decision_refs: Iterable[str] | None = None,
        known_rag_refs: Iterable[str] | None = None,
    ) -> ContextSinkValidationResult:
        normalized_sink = normalized_context_key(sink)
        result = ContextSinkValidationResult(valid=True)
        notion_export_ai_summaries: set[tuple[str, tuple[str, ...]]] = set()
        envelope_list = list(envelopes)
        if normalized_sink in {"discord_notification", "notion_export", "prompt", "rag_index", "report"}:
            context_known_evidence_refs, context_known_note_refs, context_known_rag_refs = self._context_known_source_refs(
                envelope_list,
                known_evidence_refs=known_evidence_refs,
                known_note_refs=known_note_refs,
                known_rag_refs=known_rag_refs,
            )
        else:
            context_known_evidence_refs = known_evidence_refs
            context_known_note_refs = known_note_refs
            context_known_rag_refs = known_rag_refs
        for envelope in envelope_list:
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
                    known_evidence_refs=context_known_evidence_refs,
                    known_note_refs=context_known_note_refs,
                    known_rag_refs=context_known_rag_refs,
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
                    known_evidence_refs=context_known_evidence_refs,
                    known_note_refs=context_known_note_refs,
                    known_rag_refs=context_known_rag_refs,
                )
            elif normalized_sink == "notion_inbox":
                self._validate_notion_inbox_sink(envelope, result)
            elif normalized_sink == "rag_index":
                self._validate_rag_index_sink(
                    envelope,
                    result,
                    known_evidence_refs=context_known_evidence_refs,
                    known_note_refs=context_known_note_refs,
                    known_rag_refs=context_known_rag_refs,
                )
            elif normalized_sink in {"discord_notification", "github_issue"}:
                self._validate_collaboration_sink(
                    normalized_sink,
                    envelope,
                    result,
                    known_evidence_refs=context_known_evidence_refs,
                    known_note_refs=context_known_note_refs,
                    known_rag_refs=context_known_rag_refs,
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
                    known_evidence_refs=context_known_evidence_refs,
                    known_note_refs=context_known_note_refs,
                    known_rag_refs=context_known_rag_refs,
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

    def _context_known_source_refs(
        self,
        envelopes: Iterable[ContextEnvelope],
        *,
        known_evidence_refs: Iterable[str] | None,
        known_note_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> tuple[set[str] | None, set[str], set[str]]:
        evidence_refs = (
            {canonical_source_ref(ref) for ref in known_evidence_refs if canonical_source_ref(ref)}
            if known_evidence_refs is not None
            else None
        )
        note_refs = (
            {canonical_source_ref(ref) for ref in known_note_refs if canonical_source_ref(ref)}
            if known_note_refs is not None
            else {
                envelope.ref
                for envelope in envelopes
                if envelope.kind == "operator_note" and envelope.ref.startswith("note:")
            }
        )
        rag_refs = (
            {canonical_source_ref(ref) for ref in known_rag_refs if canonical_source_ref(ref)}
            if known_rag_refs is not None
            else {envelope.ref for envelope in envelopes if envelope.kind == "rag" and envelope.ref.startswith("rag:")}
        )
        while True:
            rejected_evidence_refs: set[str] = set()
            if evidence_refs is not None:
                rejected_evidence_refs = {
                    envelope.ref
                    for envelope in envelopes
                    if envelope.kind in EVIDENCE_KINDS
                    and envelope.ref in evidence_refs
                    and (
                        is_generated_export_context(envelope)
                        or has_generated_export_path(envelope)
                        or is_generated_export_path(raw_metadata_value(envelope, "source_url"))
                        or _non_evidence_proof_source_type(envelope, EVIDENCE_KINDS)
                        or evidence_shape_omission_reason(
                            envelope,
                            allowed_authorities=EVIDENCE_CONTEXT_AUTHORITIES,
                        )
                        or _citations_with_prefixes(envelope, DISALLOWED_EVIDENCE_CITATION_PREFIXES)
                        or source_refs_metadata_errors(envelope)
                        or unresolved_ai_derived_source_ref_errors(
                            envelope.ref,
                            source_refs_metadata_values(envelope),
                            known_evidence_refs=evidence_refs,
                        )
                    )
                }
            pruned_evidence_refs = evidence_refs - rejected_evidence_refs if evidence_refs is not None else None
            rejected_note_refs = {
                envelope.ref
                for envelope in envelopes
                if envelope.kind == "operator_note"
                and envelope.ref in note_refs
                and (
                    is_generated_export_context(envelope)
                    or has_generated_export_path(envelope)
                    or is_generated_export_path(raw_metadata_value(envelope, "source_url"))
                    or operator_note_source_omission_reason(envelope)
                    or source_refs_metadata_errors(envelope)
                    or unresolved_ai_derived_source_ref_errors(
                        envelope.ref,
                        source_refs_metadata_values(envelope),
                        known_evidence_refs=pruned_evidence_refs,
                        known_note_refs=note_refs,
                        known_rag_refs=rag_refs,
                    )
                )
            }
            pruned_note_refs = note_refs - rejected_note_refs
            rejected_rag_refs = {
                envelope.ref
                for envelope in envelopes
                if envelope.kind == "rag"
                and envelope.ref in rag_refs
                and (
                    is_generated_export_context(envelope)
                    or has_generated_export_path(envelope)
                    or is_generated_export_path(raw_metadata_value(envelope, "source_url"))
                    or metadata_value_is_false(envelope, "operational_retrieval_allowed")
                    or prompt_writeup_omission_reason(envelope, role="ctf_solver_orchestrator")
                    or _non_advisory_rag_source_type(envelope)
                    or source_refs_metadata_errors(envelope)
                    or unresolved_ai_derived_source_ref_errors(
                        envelope.ref,
                        source_refs_metadata_values(envelope),
                        known_evidence_refs=pruned_evidence_refs,
                        known_note_refs=pruned_note_refs,
                        known_rag_refs=rag_refs,
                    )
                )
            }
            pruned_rag_refs = rag_refs - rejected_rag_refs
            if (
                pruned_evidence_refs == evidence_refs
                and pruned_note_refs == note_refs
                and pruned_rag_refs == rag_refs
            ):
                return evidence_refs, note_refs, rag_refs
            evidence_refs = pruned_evidence_refs
            note_refs = pruned_note_refs
            rag_refs = pruned_rag_refs

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
        restriction_reason = _sink_context_restriction_reject_reason(envelope, "evidence")
        if restriction_reason:
            self._reject(result, envelope, f"evidence sink rejects {restriction_reason} ref={envelope.ref}")
            return
        non_evidence_source_type = _non_evidence_proof_source_type(envelope, EVIDENCE_KINDS)
        if non_evidence_source_type:
            self._reject(
                result,
                envelope,
                f"evidence sink rejects source_type={non_evidence_source_type} ref={envelope.ref}",
            )
            return
        if (
            is_generated_export_context(envelope)
            or has_generated_export_path(envelope)
            or is_generated_export_path(raw_metadata_value(envelope, "source_url"))
        ):
            self._reject(result, envelope, f"evidence sink rejects generated export ref={envelope.ref}")
            return
        source_ref_errors = source_refs_metadata_errors(envelope)
        if source_ref_errors:
            self._reject(result, envelope, f"evidence sink rejects {source_ref_errors[0]} ref={envelope.ref}")
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
        restriction_reason = _sink_context_restriction_reject_reason(envelope, "finding")
        if restriction_reason:
            self._reject(result, envelope, f"finding sink rejects {restriction_reason} ref={envelope.ref}")
            return
        citations = CitationValidator(
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        ).validate([envelope])
        if not citations.valid:
            self._reject(result, envelope, "; ".join(citations.errors))
            return
        non_finding_source_type = _non_evidence_proof_source_type(envelope, frozenset({"finding"}))
        if non_finding_source_type:
            self._reject(
                result,
                envelope,
                f"finding sink rejects source_type={non_finding_source_type} ref={envelope.ref}",
            )
            return
        unsupported_citations = _citations_with_prefixes(envelope, DISALLOWED_FINDING_CITATION_PREFIXES)
        if unsupported_citations:
            self._reject(
                result,
                envelope,
                f"finding sink rejects non-evidence citation support ref={envelope.ref}: "
                f"{', '.join(unsupported_citations)}",
            )
            return
        if (
            is_generated_export_context(envelope)
            or has_generated_export_path(envelope)
            or is_generated_export_path(raw_metadata_value(envelope, "source_url"))
        ):
            self._reject(result, envelope, f"finding sink rejects generated export ref={envelope.ref}")
            return
        source_ref_errors = source_refs_metadata_errors(envelope)
        if source_ref_errors:
            self._reject(result, envelope, f"finding sink rejects {source_ref_errors[0]} ref={envelope.ref}")
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
        known_note_refs: Iterable[str] | None,
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
        if (
            is_generated_export_context(envelope)
            or has_generated_export_path(envelope)
            or is_generated_export_path(raw_metadata_value(envelope, "source_url"))
        ):
            self._reject(result, envelope, f"prompt sink rejects generated_export ref={envelope.ref}")
            return
        if metadata_value_is_false(envelope, "operational_retrieval_allowed"):
            self._reject(
                result,
                envelope,
                f"prompt sink rejects operational_retrieval_allowed=false ref={envelope.ref}",
            )
            return
        writeup_reason = prompt_writeup_omission_reason(envelope, role="ctf_solver_orchestrator")
        if writeup_reason:
            self._reject(result, envelope, f"prompt sink rejects {writeup_reason} ref={envelope.ref}")
            return
        if envelope.source_type in PROMPT_RAW_CHAT_SOURCE_TYPES:
            self._reject(result, envelope, f"prompt sink rejects raw_chat_context ref={envelope.ref}")
            return
        restriction_reason = _sink_context_restriction_reject_reason(envelope, "prompt")
        if restriction_reason:
            self._reject(result, envelope, f"prompt sink rejects {restriction_reason} ref={envelope.ref}")
            return
        note_source_reason = operator_note_source_omission_reason(envelope)
        if note_source_reason:
            self._reject(result, envelope, f"prompt sink rejects {note_source_reason} ref={envelope.ref}")
            return
        if envelope.kind == "operator_note":
            source_ref_errors = source_refs_metadata_errors(envelope)
            if source_ref_errors:
                self._reject(result, envelope, f"prompt sink rejects {source_ref_errors[0]} ref={envelope.ref}")
                return
            unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
                envelope.ref,
                source_refs_metadata_values(envelope),
                known_evidence_refs=known_evidence_refs,
                known_note_refs=known_note_refs,
                known_rag_refs=known_rag_refs,
            )
            if unresolved_source_refs:
                self._reject(result, envelope, "; ".join(unresolved_source_refs))
                return
        non_advisory_rag_source_type = _non_advisory_rag_source_type(envelope)
        if non_advisory_rag_source_type:
            self._reject(
                result,
                envelope,
                f"prompt sink rejects non_advisory_rag_source source_type={non_advisory_rag_source_type} ref={envelope.ref}",
            )
            return
        if envelope.kind == "rag":
            source_ref_errors = source_refs_metadata_errors(envelope)
            if source_ref_errors:
                self._reject(result, envelope, f"prompt sink rejects {source_ref_errors[0]} ref={envelope.ref}")
                return
            unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
                envelope.ref,
                source_refs_metadata_values(envelope),
                known_evidence_refs=known_evidence_refs,
                known_note_refs=known_note_refs,
                known_rag_refs=known_rag_refs,
            )
            if unresolved_source_refs:
                self._reject(result, envelope, "; ".join(unresolved_source_refs))
                return
        non_evidence_source_type = _non_evidence_proof_source_type(envelope, EVIDENCE_KINDS)
        if non_evidence_source_type:
            self._reject(
                result,
                envelope,
                f"prompt sink rejects proof record from source_type={non_evidence_source_type} ref={envelope.ref}",
            )
            return
        if envelope.kind in EVIDENCE_KINDS:
            unsupported_citations = _citations_with_prefixes(envelope, DISALLOWED_EVIDENCE_CITATION_PREFIXES)
            if unsupported_citations:
                self._reject(
                    result,
                    envelope,
                    "prompt sink rejects non-evidence citation support "
                    f"(including rag citation) ref={envelope.ref}",
                )
                return
            source_ref_errors = source_refs_metadata_errors(envelope)
            if source_ref_errors:
                self._reject(result, envelope, f"prompt sink rejects {source_ref_errors[0]} ref={envelope.ref}")
                return
            unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
                envelope.ref,
                source_refs_metadata_values(envelope),
                known_evidence_refs=known_evidence_refs,
            )
            if unresolved_source_refs:
                self._reject(result, envelope, "; ".join(unresolved_source_refs))
                return
        non_finding_source_type = _non_evidence_proof_source_type(envelope, frozenset({"finding"}))
        if non_finding_source_type:
            self._reject(
                result,
                envelope,
                f"prompt sink rejects proof record from source_type={non_finding_source_type} ref={envelope.ref}",
            )
            return
        if envelope.kind == "finding":
            source_ref_errors = source_refs_metadata_errors(envelope)
            if source_ref_errors:
                self._reject(result, envelope, f"prompt sink rejects {source_ref_errors[0]} ref={envelope.ref}")
                return
            unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
                envelope.ref,
                source_refs_metadata_values(envelope),
                known_evidence_refs=known_evidence_refs,
            )
            if unresolved_source_refs:
                self._reject(result, envelope, "; ".join(unresolved_source_refs))
                return
        if envelope.kind in PROMPT_AI_DERIVED_KINDS:
            placeholder_citations = placeholder_source_refs(envelope.citations)
            if placeholder_citations:
                self._reject(
                    result,
                    envelope,
                    "prompt sink rejects placeholder citations for AI-derived context "
                    f"ref={envelope.ref}: {', '.join(placeholder_citations)}",
                )
                return
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
                known_note_refs=known_note_refs,
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
        restriction_reason = _sink_context_restriction_reject_reason(envelope, "task_metadata")
        if restriction_reason:
            self._reject(result, envelope, f"task_metadata rejects {restriction_reason} ref={envelope.ref}")
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
        known_note_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        restriction_reason = _sink_context_restriction_reject_reason(envelope, "notion_export")
        if restriction_reason:
            result.quarantined_refs.append(envelope.ref)
            result.errors.append(f"notion_export quarantines {envelope.ref}: {restriction_reason}")
            return
        if is_generated_export_path(raw_metadata_value(envelope, "source_url")):
            result.quarantined_refs.append(envelope.ref)
            result.errors.append(f"notion_export quarantines {envelope.ref}: generated export recursion")
            return
        if envelope.kind == "operator_note":
            source_ref_errors = source_refs_metadata_errors(envelope)
            if source_ref_errors:
                result.quarantined_refs.append(envelope.ref)
                result.errors.append(f"notion_export quarantines {envelope.ref}: {source_ref_errors[0]}")
                return
            unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
                envelope.ref,
                source_refs_metadata_values(envelope),
                known_evidence_refs=known_evidence_refs,
                known_note_refs=known_note_refs,
                known_rag_refs=known_rag_refs,
            )
            if unresolved_source_refs:
                result.quarantined_refs.append(envelope.ref)
                result.errors.append("; ".join(unresolved_source_refs))
                return
        decision = validate_notion_export_envelope(
            envelope,
            seen_ai_summaries,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
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
        restriction_reason = _sink_context_restriction_reject_reason(envelope, "notion_inbox")
        if restriction_reason:
            self._reject(result, envelope, f"notion_inbox rejects {restriction_reason} ref={envelope.ref}")
            return
        if has_generated_export_path(envelope) or is_generated_export_path(raw_metadata_value(envelope, "source_url")):
            self._reject(result, envelope, f"notion_inbox rejects generated export ref={envelope.ref}")
            return
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
        known_evidence_refs: Iterable[str] | None,
        known_note_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        decision = validate_rag_index_sink(
            envelope,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
            known_rag_refs=known_rag_refs,
        )
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
        known_note_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        restriction_reason = _sink_context_restriction_reject_reason(envelope, sink)
        if restriction_reason:
            self._reject(result, envelope, f"{sink} rejects {restriction_reason} ref={envelope.ref}")
            return
        if is_generated_export_path(raw_metadata_value(envelope, "source_url")):
            self._reject(result, envelope, f"{sink} rejects generated export ref={envelope.ref}")
            return
        if sink == "discord_notification" and envelope.kind == "operator_note":
            source_ref_errors = source_refs_metadata_errors(envelope)
            if source_ref_errors:
                self._reject(result, envelope, f"discord_notification rejects {source_ref_errors[0]} ref={envelope.ref}")
                return
            unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
                envelope.ref,
                source_refs_metadata_values(envelope),
                known_evidence_refs=known_evidence_refs,
                known_note_refs=known_note_refs,
                known_rag_refs=known_rag_refs,
            )
            if unresolved_source_refs:
                self._reject(result, envelope, "; ".join(unresolved_source_refs))
                return
        decision = validate_collaboration_sink(
            sink,
            envelope,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
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
        restriction_reason = _sink_context_restriction_reject_reason(envelope, "github_ledger")
        if restriction_reason:
            self._reject(result, envelope, f"github_ledger rejects {restriction_reason} ref={envelope.ref}")
            return
        if has_generated_export_path(envelope) or is_generated_export_path(raw_metadata_value(envelope, "source_url")):
            self._reject(result, envelope, f"github_ledger rejects generated export ref={envelope.ref}")
            return
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
        restriction_reason = _sink_context_restriction_reject_reason(envelope, "ctfd_submission")
        if restriction_reason:
            self._reject(result, envelope, f"ctfd_submission rejects {restriction_reason} ref={envelope.ref}")
            return
        if has_generated_export_path(envelope) or is_generated_export_path(raw_metadata_value(envelope, "source_url")):
            self._reject(result, envelope, f"ctfd_submission rejects generated export ref={envelope.ref}")
            return
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
        restriction_reason = _sink_context_restriction_reject_reason(envelope, "ctfd_registry")
        if restriction_reason:
            self._reject(result, envelope, f"ctfd_registry rejects {restriction_reason} ref={envelope.ref}")
            return
        if has_generated_export_path(envelope) or is_generated_export_path(raw_metadata_value(envelope, "source_url")):
            self._reject(result, envelope, f"ctfd_registry rejects generated export ref={envelope.ref}")
            return
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
        known_note_refs: Iterable[str] | None,
        known_rag_refs: Iterable[str] | None,
    ) -> None:
        restriction_reason = _sink_context_restriction_reject_reason(envelope, "report")
        if restriction_reason:
            self._reject(result, envelope, f"report sink rejects {restriction_reason} ref={envelope.ref}")
            return
        if is_generated_export_path(raw_metadata_value(envelope, "source_url")):
            self._reject(result, envelope, f"report sink rejects generated export ref={envelope.ref}")
            return
        if envelope.kind == "operator_note":
            source_ref_errors = source_refs_metadata_errors(envelope)
            if source_ref_errors:
                self._reject(result, envelope, f"report sink rejects {source_ref_errors[0]} ref={envelope.ref}")
                return
            unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
                envelope.ref,
                source_refs_metadata_values(envelope),
                known_evidence_refs=known_evidence_refs,
                known_note_refs=known_note_refs,
                known_rag_refs=known_rag_refs,
            )
            if unresolved_source_refs:
                self._reject(result, envelope, "; ".join(unresolved_source_refs))
                return
        if envelope.kind == "rag":
            source_ref_errors = source_refs_metadata_errors(envelope)
            if source_ref_errors:
                self._reject(result, envelope, f"report sink rejects {source_ref_errors[0]} ref={envelope.ref}")
                return
            unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
                envelope.ref,
                source_refs_metadata_values(envelope),
                known_evidence_refs=known_evidence_refs,
                known_note_refs=known_note_refs,
                known_rag_refs=known_rag_refs,
            )
            if unresolved_source_refs:
                self._reject(result, envelope, "; ".join(unresolved_source_refs))
                return
        decision = validate_report_sink(
            envelope,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
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


def _non_evidence_proof_source_type(envelope: ContextEnvelope, kinds: frozenset[str]) -> str:
    if envelope.kind not in kinds:
        return ""
    source_types = {normalized_context_key(envelope.source_type), *_metadata_text_values(envelope, "source_type")}
    return next(iter(sorted(source_types & NON_EVIDENCE_SOURCE_TYPES)), "")


def _non_advisory_rag_source_type(envelope: ContextEnvelope) -> str:
    if envelope.kind != "rag":
        return ""
    source_types = {normalized_context_key(envelope.source_type), *_metadata_text_values(envelope, "source_type")}
    if normalized_context_key(envelope.source_type) in RAG_ADVISORY_SOURCE_TYPES:
        source_types -= RAG_CHUNK_FORMAT_SOURCE_TYPES
    if normalized_context_key(envelope.source_type) == "vuln_intel":
        source_types -= RAG_CHUNK_VULN_INTEL_SOURCE_TYPES
    return next(iter(sorted(source_types - RAG_ADVISORY_SOURCE_TYPES)), "")


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
    if "source_type" in normalized_names:
        normalized_names.add("source_types")
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


def _sink_context_restriction_reject_reason(envelope: ContextEnvelope, sink: str) -> str:
    context_names = normalized_context_keys((sink, envelope.purpose))
    invalid_for = normalized_context_keys(envelope.invalid_for)
    if invalid_for & context_names:
        return f"invalid_for excludes {sink}"
    valid_for = normalized_context_keys(envelope.valid_for)
    if valid_for and not valid_for & context_names:
        return f"valid_for excludes {sink}"
    return ""


def _unresolved_evidence_citations(
    envelope: ContextEnvelope,
    known_evidence_refs: Iterable[str] | None,
) -> list[str]:
    if known_evidence_refs is None:
        return []
    known_refs = {_canonical_evidence_ref(ref) for ref in known_evidence_refs if _canonical_evidence_ref(ref)}
    known_refs.add(envelope.ref)
    citations = _citations_with_prefixes(envelope, (EVIDENCE_REF_PREFIX,))
    return sorted(set(citations) - known_refs)


def _canonical_evidence_ref(value: object) -> str:
    ref = str(value or "").strip()
    if ref.lower().startswith(EVIDENCE_REF_PREFIX):
        return f"{EVIDENCE_REF_PREFIX}{ref[len(EVIDENCE_REF_PREFIX):].strip()}"
    return ref
