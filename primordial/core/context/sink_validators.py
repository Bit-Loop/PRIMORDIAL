from __future__ import annotations

from typing import Iterable

from primordial.core.context.authority_refs import unresolved_policy_decision_citation_errors
from primordial.core.context.bindings import current_context_binding_error
from primordial.core.context.citations import CitationValidator
from primordial.core.context.collaboration import validate_collaboration_sink
from primordial.core.context.ctfd import validate_ctfd_registry_sink, validate_ctfd_submission_sink
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.evidence_shape import (
    EVIDENCE_AUTHORITIES,
    EVIDENCE_CONTEXT_AUTHORITIES,
    EVIDENCE_REF_PREFIX,
    FINDING_REF_PREFIX,
)
from primordial.core.context.generated_exports import (
    has_generated_export_path,
    is_generated_export_context,
    is_generated_export_path,
)
from primordial.core.context.github_ledger import validate_github_ledger_envelope
from primordial.core.context.metadata_flags import raw_metadata_value
from primordial.core.context.notion_export import validate_notion_export_envelope
from primordial.core.context.notion_inbox import validate_notion_inbox_envelope
from primordial.core.context.prompt_sink import PromptSinkChecks, validate_prompt_sink as validate_prompt_sink_envelope
from primordial.core.context.rag_index import validate_rag_index_sink
from primordial.core.context.report import validate_report_sink
from primordial.core.context.sink_helpers import (
    citations_with_prefixes,
    non_advisory_rag_source_type,
    non_evidence_proof_source_type,
    reject_sink_envelope,
    sink_context_restriction_reject_reason,
    unresolved_evidence_citations,
)
from primordial.core.context.sink_types import (
    DISALLOWED_EVIDENCE_CITATION_PREFIXES,
    DISALLOWED_FINDING_CITATION_PREFIXES,
    EVIDENCE_KINDS,
    PROMPT_AI_DERIVED_KINDS,
    PROMPT_RAW_CHAT_SOURCE_TYPES,
    TASK_METADATA_KINDS,
    ContextSinkValidationResult,
)
from primordial.core.context.source_refs import (
    source_refs_metadata_errors,
    source_refs_metadata_values,
    unresolved_ai_derived_source_ref_errors,
)
from primordial.core.context.task_metadata import task_metadata_errors


def validate_evidence_sink(
    envelope: ContextEnvelope,
    result: ContextSinkValidationResult,
    *,
    known_evidence_refs: Iterable[str] | None,
) -> None:
    if envelope.kind not in EVIDENCE_KINDS:
        reject_sink_envelope(result, envelope, f"evidence sink rejects kind={envelope.kind} ref={envelope.ref}")
        return
    if envelope.authority not in EVIDENCE_AUTHORITIES:
        reject_sink_envelope(result, envelope, f"evidence sink rejects authority={envelope.authority} ref={envelope.ref}")
        return
    if not envelope.ref.startswith(EVIDENCE_REF_PREFIX):
        reject_sink_envelope(result, envelope, f"evidence sink requires evidence:<id> ref, got {envelope.ref}")
        return
    restriction_reason = sink_context_restriction_reject_reason(envelope, "evidence")
    if restriction_reason:
        reject_sink_envelope(result, envelope, f"evidence sink rejects {restriction_reason} ref={envelope.ref}")
        return
    non_evidence_source_type = non_evidence_proof_source_type(envelope, EVIDENCE_KINDS)
    if non_evidence_source_type:
        reject_sink_envelope(
            result,
            envelope,
            f"evidence sink rejects source_type={non_evidence_source_type} ref={envelope.ref}",
        )
        return
    if _is_generated_export_source(envelope):
        reject_sink_envelope(result, envelope, f"evidence sink rejects generated export ref={envelope.ref}")
        return
    source_ref_errors = source_refs_metadata_errors(envelope)
    if source_ref_errors:
        reject_sink_envelope(result, envelope, f"evidence sink rejects {source_ref_errors[0]} ref={envelope.ref}")
        return
    unsupported_citations = citations_with_prefixes(envelope, DISALLOWED_EVIDENCE_CITATION_PREFIXES)
    if unsupported_citations:
        reject_sink_envelope(
            result,
            envelope,
            "evidence sink rejects non-evidence citation support "
            f"(including rag citation) ref={envelope.ref}",
        )
        return
    unresolved_citations = unresolved_evidence_citations(envelope, known_evidence_refs)
    if unresolved_citations:
        reject_sink_envelope(
            result,
            envelope,
            "evidence sink rejects unresolved evidence citation(s) "
            f"ref={envelope.ref}: {', '.join(unresolved_citations)}",
        )
        return
    binding_reason = current_context_binding_error(envelope, proof_records=True)
    if binding_reason:
        reject_sink_envelope(result, envelope, f"evidence sink rejects {binding_reason} context ref={envelope.ref}")
        return
    result.accepted_refs.append(envelope.ref)


def validate_finding_sink(
    envelope: ContextEnvelope,
    result: ContextSinkValidationResult,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> None:
    if envelope.kind != "finding":
        reject_sink_envelope(result, envelope, f"finding sink rejects kind={envelope.kind} ref={envelope.ref}")
        return
    if not envelope.ref.startswith(FINDING_REF_PREFIX):
        reject_sink_envelope(result, envelope, f"finding sink requires {FINDING_REF_PREFIX}<id> ref, got {envelope.ref}")
        return
    restriction_reason = sink_context_restriction_reject_reason(envelope, "finding")
    if restriction_reason:
        reject_sink_envelope(result, envelope, f"finding sink rejects {restriction_reason} ref={envelope.ref}")
        return
    citations = CitationValidator(known_evidence_refs=known_evidence_refs, known_rag_refs=known_rag_refs).validate(
        [envelope]
    )
    if not citations.valid:
        reject_sink_envelope(result, envelope, "; ".join(citations.errors))
        return
    non_finding_source_type = non_evidence_proof_source_type(envelope, frozenset({"finding"}))
    if non_finding_source_type:
        reject_sink_envelope(
            result,
            envelope,
            f"finding sink rejects source_type={non_finding_source_type} ref={envelope.ref}",
        )
        return
    unsupported_citations = citations_with_prefixes(envelope, DISALLOWED_FINDING_CITATION_PREFIXES)
    if unsupported_citations:
        reject_sink_envelope(
            result,
            envelope,
            f"finding sink rejects non-evidence citation support ref={envelope.ref}: "
            f"{', '.join(unsupported_citations)}",
        )
        return
    if _is_generated_export_source(envelope):
        reject_sink_envelope(result, envelope, f"finding sink rejects generated export ref={envelope.ref}")
        return
    source_ref_errors = source_refs_metadata_errors(envelope)
    if source_ref_errors:
        reject_sink_envelope(result, envelope, f"finding sink rejects {source_ref_errors[0]} ref={envelope.ref}")
        return
    binding_reason = current_context_binding_error(envelope, proof_records=True)
    if binding_reason:
        reject_sink_envelope(result, envelope, f"finding sink rejects {binding_reason} context ref={envelope.ref}")
        return
    result.accepted_refs.append(envelope.ref)


def validate_prompt_sink_payload(
    envelope: ContextEnvelope,
    result: ContextSinkValidationResult,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> None:
    decision = validate_prompt_sink_envelope(
        envelope,
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
        checks=PromptSinkChecks(
            evidence_kinds=EVIDENCE_KINDS,
            evidence_context_authorities=EVIDENCE_CONTEXT_AUTHORITIES,
            disallowed_evidence_citation_prefixes=DISALLOWED_EVIDENCE_CITATION_PREFIXES,
            prompt_raw_chat_source_types=PROMPT_RAW_CHAT_SOURCE_TYPES,
            prompt_ai_derived_kinds=PROMPT_AI_DERIVED_KINDS,
            citations_with_prefixes=citations_with_prefixes,
            context_restriction_reject_reason=sink_context_restriction_reject_reason,
            non_evidence_proof_source_type=non_evidence_proof_source_type,
            non_advisory_rag_source_type=non_advisory_rag_source_type,
        ),
    )
    if decision.action == "accept":
        result.accepted_refs.append(envelope.ref)
        return
    reject_sink_envelope(result, envelope, decision.message)


def validate_task_metadata_sink(
    envelope: ContextEnvelope,
    result: ContextSinkValidationResult,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_policy_decision_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> None:
    if envelope.kind not in TASK_METADATA_KINDS:
        reject_sink_envelope(result, envelope, f"task_metadata sink rejects kind={envelope.kind} ref={envelope.ref}")
        return
    restriction_reason = sink_context_restriction_reject_reason(envelope, "task_metadata")
    if restriction_reason:
        reject_sink_envelope(result, envelope, f"task_metadata rejects {restriction_reason} ref={envelope.ref}")
        return
    citations = CitationValidator(known_evidence_refs=known_evidence_refs, known_rag_refs=known_rag_refs).validate(
        [envelope]
    )
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


def validate_notion_export_sink_payload(
    envelope: ContextEnvelope,
    result: ContextSinkValidationResult,
    seen_ai_summaries: set[tuple[str, tuple[str, ...]]],
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> None:
    restriction_reason = sink_context_restriction_reject_reason(envelope, "notion_export")
    if restriction_reason:
        _quarantine(result, envelope, f"notion_export quarantines {envelope.ref}: {restriction_reason}")
        return
    if is_generated_export_path(raw_metadata_value(envelope, "source_url")):
        _quarantine(result, envelope, f"notion_export quarantines {envelope.ref}: generated export recursion")
        return
    if envelope.kind == "operator_note" and _reject_unresolved_source_refs(
        result,
        envelope,
        "notion_export quarantines",
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
        quarantine=True,
    ):
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
    _quarantine(result, envelope, decision.message)


def validate_notion_inbox_sink_payload(envelope: ContextEnvelope, result: ContextSinkValidationResult) -> None:
    restriction_reason = sink_context_restriction_reject_reason(envelope, "notion_inbox")
    if restriction_reason:
        reject_sink_envelope(result, envelope, f"notion_inbox rejects {restriction_reason} ref={envelope.ref}")
        return
    if has_generated_export_path(envelope) or is_generated_export_path(raw_metadata_value(envelope, "source_url")):
        reject_sink_envelope(result, envelope, f"notion_inbox rejects generated export ref={envelope.ref}")
        return
    decision = validate_notion_inbox_envelope(envelope)
    if decision.action == "accept":
        result.accepted_refs.append(envelope.ref)
    elif decision.action == "quarantine":
        _quarantine(result, envelope, decision.message)
    else:
        reject_sink_envelope(result, envelope, decision.message)


def validate_rag_index_sink_payload(
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
    reject_sink_envelope(result, envelope, decision.message)


def validate_collaboration_sink_payload(
    sink: str,
    envelope: ContextEnvelope,
    result: ContextSinkValidationResult,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> None:
    restriction_reason = sink_context_restriction_reject_reason(envelope, sink)
    if restriction_reason:
        reject_sink_envelope(result, envelope, f"{sink} rejects {restriction_reason} ref={envelope.ref}")
        return
    if is_generated_export_path(raw_metadata_value(envelope, "source_url")):
        reject_sink_envelope(result, envelope, f"{sink} rejects generated export ref={envelope.ref}")
        return
    if sink == "discord_notification" and envelope.kind == "operator_note":
        if _reject_unresolved_source_refs(
            result,
            envelope,
            "discord_notification rejects",
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
            known_rag_refs=known_rag_refs,
        ):
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
    elif decision.action == "reject":
        reject_sink_envelope(result, envelope, decision.message)
    elif decision.action == "quarantine":
        _quarantine(result, envelope, decision.message)


def validate_github_ledger_sink_payload(envelope: ContextEnvelope, result: ContextSinkValidationResult) -> None:
    restriction_reason = sink_context_restriction_reject_reason(envelope, "github_ledger")
    if restriction_reason:
        reject_sink_envelope(result, envelope, f"github_ledger rejects {restriction_reason} ref={envelope.ref}")
        return
    if has_generated_export_path(envelope) or is_generated_export_path(raw_metadata_value(envelope, "source_url")):
        reject_sink_envelope(result, envelope, f"github_ledger rejects generated export ref={envelope.ref}")
        return
    decision = validate_github_ledger_envelope(envelope)
    if decision.action == "accept":
        result.accepted_refs.append(envelope.ref)
        return
    reject_sink_envelope(result, envelope, decision.message)


def validate_ctfd_submission_sink_payload(envelope: ContextEnvelope, result: ContextSinkValidationResult) -> None:
    _validate_ctfd_sink(
        envelope,
        result,
        sink="ctfd_submission",
        validator=validate_ctfd_submission_sink,
    )


def validate_ctfd_registry_sink_payload(envelope: ContextEnvelope, result: ContextSinkValidationResult) -> None:
    _validate_ctfd_sink(
        envelope,
        result,
        sink="ctfd_registry",
        validator=validate_ctfd_registry_sink,
    )


def validate_report_sink_payload(
    envelope: ContextEnvelope,
    result: ContextSinkValidationResult,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> None:
    restriction_reason = sink_context_restriction_reject_reason(envelope, "report")
    if restriction_reason:
        reject_sink_envelope(result, envelope, f"report sink rejects {restriction_reason} ref={envelope.ref}")
        return
    if is_generated_export_path(raw_metadata_value(envelope, "source_url")):
        reject_sink_envelope(result, envelope, f"report sink rejects generated export ref={envelope.ref}")
        return
    if envelope.kind in {"operator_note", "rag"} and _reject_unresolved_source_refs(
        result,
        envelope,
        "report sink rejects",
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    ):
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
    reject_sink_envelope(result, envelope, decision.message)


def _validate_ctfd_sink(
    envelope: ContextEnvelope,
    result: ContextSinkValidationResult,
    *,
    sink: str,
    validator: object,
) -> None:
    restriction_reason = sink_context_restriction_reject_reason(envelope, sink)
    if restriction_reason:
        reject_sink_envelope(result, envelope, f"{sink} rejects {restriction_reason} ref={envelope.ref}")
        return
    if has_generated_export_path(envelope) or is_generated_export_path(raw_metadata_value(envelope, "source_url")):
        reject_sink_envelope(result, envelope, f"{sink} rejects generated export ref={envelope.ref}")
        return
    decision = validator(envelope)
    if decision.action == "accept":
        result.accepted_refs.append(envelope.ref)
        return
    reject_sink_envelope(result, envelope, decision.message)


def _reject_unresolved_source_refs(
    result: ContextSinkValidationResult,
    envelope: ContextEnvelope,
    prefix: str,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
    quarantine: bool = False,
) -> bool:
    source_ref_errors = source_refs_metadata_errors(envelope)
    if source_ref_errors:
        message = f"{prefix} {source_ref_errors[0]} ref={envelope.ref}"
        _quarantine(result, envelope, message) if quarantine else reject_sink_envelope(result, envelope, message)
        return True
    unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
        envelope.ref,
        source_refs_metadata_values(envelope),
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )
    if unresolved_source_refs:
        message = "; ".join(unresolved_source_refs)
        _quarantine(result, envelope, message) if quarantine else reject_sink_envelope(result, envelope, message)
        return True
    return False


def _is_generated_export_source(envelope: ContextEnvelope) -> bool:
    return (
        is_generated_export_context(envelope)
        or has_generated_export_path(envelope)
        or is_generated_export_path(raw_metadata_value(envelope, "source_url"))
    )


def _quarantine(result: ContextSinkValidationResult, envelope: ContextEnvelope, message: str) -> None:
    result.quarantined_refs.append(envelope.ref)
    result.errors.append(message)
