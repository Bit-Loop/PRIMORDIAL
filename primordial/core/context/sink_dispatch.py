from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_context_key
from primordial.core.context.purposes import OPERATIONAL_CONTEXT_PURPOSES


CONTEXT_SOURCE_REF_SINKS = frozenset({"discord_notification", "notion_export", "prompt", "rag_index", "report"})


@dataclass(frozen=True, slots=True)
class SinkKnownRefs:
    evidence_refs: Iterable[str] | None
    note_refs: Iterable[str] | None
    rag_refs: Iterable[str] | None


def validate_sink_envelopes(
    validator: Any,
    *,
    normalized_sink: str,
    envelopes: list[ContextEnvelope],
    result: Any,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_policy_decision_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> Any:
    known_refs = _known_refs_for_sink(
        validator,
        normalized_sink,
        envelopes,
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )
    notion_export_ai_summaries: set[tuple[str, tuple[str, ...]]] = set()
    for envelope in envelopes:
        _validate_envelope_for_sink(
            validator,
            normalized_sink,
            envelope,
            result,
            known_refs=known_refs,
            known_policy_decision_refs=known_policy_decision_refs,
            notion_export_ai_summaries=notion_export_ai_summaries,
        )
    return _finalize_result(result)


def _known_refs_for_sink(
    validator: Any,
    normalized_sink: str,
    envelopes: Iterable[ContextEnvelope],
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> SinkKnownRefs:
    if normalized_sink not in CONTEXT_SOURCE_REF_SINKS:
        return SinkKnownRefs(known_evidence_refs, known_note_refs, known_rag_refs)
    evidence_refs, note_refs, rag_refs = validator._context_known_source_refs(
        envelopes,
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )
    return SinkKnownRefs(evidence_refs, note_refs, rag_refs)


def _validate_envelope_for_sink(
    validator: Any,
    normalized_sink: str,
    envelope: ContextEnvelope,
    result: Any,
    *,
    known_refs: SinkKnownRefs,
    known_policy_decision_refs: Iterable[str] | None,
    notion_export_ai_summaries: set[tuple[str, tuple[str, ...]]],
) -> None:
    if validator._has_sink_mismatch(normalized_sink, envelope):
        _reject_sink_mismatch(validator, result, envelope, normalized_sink)
        return
    if _validate_core_sink(
        validator,
        normalized_sink,
        envelope,
        result,
        known_refs=known_refs,
        known_policy_decision_refs=known_policy_decision_refs,
        notion_export_ai_summaries=notion_export_ai_summaries,
    ):
        return
    if _validate_projection_sink(validator, normalized_sink, envelope, result):
        return
    _validate_unknown_sink(validator, normalized_sink, envelope, result)


def _validate_core_sink(
    validator: Any,
    normalized_sink: str,
    envelope: ContextEnvelope,
    result: Any,
    *,
    known_refs: SinkKnownRefs,
    known_policy_decision_refs: Iterable[str] | None,
    notion_export_ai_summaries: set[tuple[str, tuple[str, ...]]],
) -> bool:
    if normalized_sink == "evidence":
        validator._validate_evidence_sink(envelope, result, known_evidence_refs=known_refs.evidence_refs)
    elif normalized_sink == "prompt":
        _validate_prompt_sink(validator, envelope, result, known_refs)
    elif normalized_sink == "finding":
        validator._validate_finding_sink(
            envelope,
            result,
            known_evidence_refs=known_refs.evidence_refs,
            known_rag_refs=known_refs.rag_refs,
        )
    elif normalized_sink == "task_metadata":
        validator._validate_task_metadata_sink(
            envelope,
            result,
            known_evidence_refs=known_refs.evidence_refs,
            known_policy_decision_refs=known_policy_decision_refs,
            known_rag_refs=known_refs.rag_refs,
        )
    elif normalized_sink == "notion_export":
        _validate_notion_export_sink(validator, envelope, result, known_refs, notion_export_ai_summaries)
    elif normalized_sink == "rag_index":
        _validate_rag_index_sink(validator, envelope, result, known_refs)
    elif normalized_sink in {"discord_notification", "github_issue"}:
        _validate_collaboration_sink(validator, normalized_sink, envelope, result, known_refs)
    elif normalized_sink == "report":
        _validate_report_sink(validator, envelope, result, known_refs)
    else:
        return False
    return True


def _validate_prompt_sink(validator: Any, envelope: ContextEnvelope, result: Any, known_refs: SinkKnownRefs) -> None:
    validator._validate_prompt_sink(
        envelope,
        result,
        known_evidence_refs=known_refs.evidence_refs,
        known_note_refs=known_refs.note_refs,
        known_rag_refs=known_refs.rag_refs,
    )


def _validate_notion_export_sink(
    validator: Any,
    envelope: ContextEnvelope,
    result: Any,
    known_refs: SinkKnownRefs,
    notion_export_ai_summaries: set[tuple[str, tuple[str, ...]]],
) -> None:
    validator._validate_notion_export_sink(
        envelope,
        result,
        notion_export_ai_summaries,
        known_evidence_refs=known_refs.evidence_refs,
        known_note_refs=known_refs.note_refs,
        known_rag_refs=known_refs.rag_refs,
    )


def _validate_rag_index_sink(validator: Any, envelope: ContextEnvelope, result: Any, known_refs: SinkKnownRefs) -> None:
    validator._validate_rag_index_sink(
        envelope,
        result,
        known_evidence_refs=known_refs.evidence_refs,
        known_note_refs=known_refs.note_refs,
        known_rag_refs=known_refs.rag_refs,
    )


def _validate_collaboration_sink(
    validator: Any,
    normalized_sink: str,
    envelope: ContextEnvelope,
    result: Any,
    known_refs: SinkKnownRefs,
) -> None:
    validator._validate_collaboration_sink(
        normalized_sink,
        envelope,
        result,
        known_evidence_refs=known_refs.evidence_refs,
        known_note_refs=known_refs.note_refs,
        known_rag_refs=known_refs.rag_refs,
    )


def _validate_report_sink(validator: Any, envelope: ContextEnvelope, result: Any, known_refs: SinkKnownRefs) -> None:
    validator._validate_report_sink(
        envelope,
        result,
        known_evidence_refs=known_refs.evidence_refs,
        known_note_refs=known_refs.note_refs,
        known_rag_refs=known_refs.rag_refs,
    )


def _validate_projection_sink(validator: Any, normalized_sink: str, envelope: ContextEnvelope, result: Any) -> bool:
    if normalized_sink == "notion_inbox":
        validator._validate_notion_inbox_sink(envelope, result)
    elif normalized_sink == "github_ledger":
        validator._validate_github_ledger_sink(envelope, result)
    elif normalized_sink == "ctfd_registry":
        validator._validate_ctfd_registry_sink(envelope, result)
    elif normalized_sink == "ctfd_submission":
        validator._validate_ctfd_submission_sink(envelope, result)
    else:
        return False
    return True


def _validate_unknown_sink(validator: Any, normalized_sink: str, envelope: ContextEnvelope, result: Any) -> None:
    if (
        normalized_sink in OPERATIONAL_CONTEXT_PURPOSES
        or normalized_context_key(envelope.purpose) in OPERATIONAL_CONTEXT_PURPOSES
    ):
        validator._reject(
            result,
            envelope,
            f"unknown operational sink {normalized_sink or '<empty>'} ref={envelope.ref}",
        )
        return
    result.accepted_refs.append(envelope.ref)
    result.warnings.append(f"no specialized sink rules for {normalized_sink or '<empty>'}")


def _reject_sink_mismatch(validator: Any, result: Any, envelope: ContextEnvelope, normalized_sink: str) -> None:
    validator._reject(
        result,
        envelope,
        f"sink mismatch ref={envelope.ref} envelope.sink={envelope.sink or '<empty>'} "
        f"requested={normalized_sink or '<empty>'}",
    )


def _finalize_result(result: Any) -> Any:
    result.accepted_refs = sorted(set(result.accepted_refs))
    result.rejected_refs = sorted(set(result.rejected_refs))
    result.quarantined_refs = sorted(set(result.quarantined_refs))
    result.valid = not result.errors
    return result
