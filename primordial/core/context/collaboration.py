from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from primordial.core.context.bindings import TARGET_FACT_METADATA_KEYS, current_context_binding_error
from primordial.core.context.citations import CitationValidator
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.generated_exports import has_generated_export_path, is_generated_export_context
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys
from primordial.core.context.operator_notes import operator_note_source_omission_reason
from primordial.core.context.poison import has_context_flag
from primordial.core.context.source_refs import (
    source_refs_metadata_errors,
    source_refs_metadata_values,
    unresolved_ai_derived_source_ref_errors,
)
from primordial.core.context.source_types import (
    COLLABORATION_SOURCE_TYPES,
    EVIDENCE_PROOF_KINDS,
    NON_EVIDENCE_SOURCE_TYPES,
    TRUTH_LIKE_AUTHORITIES,
)
from primordial.core.context.writeup_policy import prompt_writeup_omission_reason


ADVISORY_SOURCE_TYPES = frozenset({"vuln_intel", "methodology_doc", "writeup", "ai_output", "chat"})
AI_SUMMARY_KINDS = frozenset({"model_summary", "hypothesis", "candidate_task"})
DISCORD_SOURCE_REF_VALIDATED_KINDS = AI_SUMMARY_KINDS | frozenset({"operator_note", "rag"})
DISCORD_ADVISORY_KINDS = AI_SUMMARY_KINDS | frozenset({"rag"})
DISCORD_ADVISORY_LABELS = frozenset({"advisory", "unverified", "derived"})
DISCORD_EXTERNAL_COLLABORATION_SOURCE_TYPES = COLLABORATION_SOURCE_TYPES | frozenset({"ctfd"})
DISCORD_EXTERNAL_COLLABORATION_LABELS = frozenset(
    {"advisory", "collaboration", "engineering_context", "external", "scoreboard", "unverified"}
)
DISCORD_AUTHORITY_KINDS = EVIDENCE_PROOF_KINDS | frozenset(
    {"approval", "authority", "operator_intent", "policy_decision", "scope"}
)
GITHUB_ISSUE_KINDS = frozenset({"github_ref", "engineering_context", "failure_analysis", "patch_proposal", "test_status"})
GITHUB_ISSUE_SOURCE_TYPES = frozenset(
    {
        "engineering_context",
        "failure_analysis",
        "github",
        "github_project_context",
        "parser_failure",
        "patch_history",
        "patch_proposal",
        "regression_failure",
        "test_status",
    }
)
GITHUB_ISSUE_CONTEXT_TYPES = frozenset(
    {
        "engineering_context",
        "failure_analysis",
        "patch_history",
        "patch_proposal",
        "parser_failure",
        "regression_failure",
        "test_status",
    }
)
GITHUB_AUTHORITY_FLAGS = (
    "creates_target_authority",
    "mutates_target_truth",
    "authorizes_target_action",
    "changes_scope",
    "changes_operator_intent",
    "creates_approval",
)
SENSITIVE_GITHUB_FLAGS = (
    "contains_sensitive_raw_target_evidence",
    "contains_raw_flag",
    "contains_secret",
    "contains_credential",
    "hidden_solution_material",
)
DISCORD_EVIDENCE_RENDERING_FLAGS = ("renders_as_evidence",)
DISCORD_APPROVAL_FLAGS = ("implies_approval",)
REDACTION_FLAGS = ("redacted", "evidence_refs_redacted")


@dataclass(frozen=True, slots=True)
class CollaborationSinkDecision:
    action: str
    message: str = ""


def validate_collaboration_sink(
    sink: str,
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None = None,
    known_note_refs: Iterable[str] | None = None,
    known_rag_refs: Iterable[str] | None = None,
) -> CollaborationSinkDecision:
    normalized_sink = str(sink or "").strip().lower()
    if normalized_sink == "discord_notification":
        return _validate_discord_notification(
            envelope,
            known_evidence_refs=known_evidence_refs,
            known_note_refs=known_note_refs,
            known_rag_refs=known_rag_refs,
        )
    if normalized_sink == "github_issue":
        return _validate_github_issue(envelope)
    return CollaborationSinkDecision("accept")


def _validate_discord_notification(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> CollaborationSinkDecision:
    if is_generated_export_context(envelope) or has_generated_export_path(envelope):
        return CollaborationSinkDecision(
            "reject",
            f"discord_notification rejects generated export recursion ref={envelope.ref}",
        )
    if has_context_flag(envelope, DISCORD_EVIDENCE_RENDERING_FLAGS):
        return CollaborationSinkDecision(
            "reject",
            f"discord_notification must not render derived context as evidence ref={envelope.ref}",
        )
    if has_context_flag(envelope, DISCORD_APPROVAL_FLAGS):
        return CollaborationSinkDecision("reject", f"discord_notification must not imply approval ref={envelope.ref}")
    if _is_non_evidence_source_proof_record(envelope):
        return CollaborationSinkDecision(
            "reject",
            f"discord_notification rejects non-evidence source proof record ref={envelope.ref}",
        )
    if _is_non_authority_source_authority_record(envelope):
        return CollaborationSinkDecision(
            "reject",
            f"discord_notification rejects non-authority source authority record ref={envelope.ref}",
        )
    note_source_reason = operator_note_source_omission_reason(envelope)
    if note_source_reason:
        return CollaborationSinkDecision(
            "reject",
            f"discord_notification rejects {note_source_reason} ref={envelope.ref}",
        )
    writeup_reason = prompt_writeup_omission_reason(envelope, role="report_writer")
    if writeup_reason:
        return CollaborationSinkDecision(
            "reject",
            f"discord_notification rejects {writeup_reason} ref={envelope.ref}",
        )
    if envelope.kind in AI_SUMMARY_KINDS and _has_truth_like_authority(envelope):
        return CollaborationSinkDecision(
            "reject",
            f"discord_notification rejects truth-like authority on AI-derived context ref={envelope.ref}",
        )
    binding_reason = current_context_binding_error(envelope, proof_records=True, target_facts=True)
    if binding_reason:
        return CollaborationSinkDecision(
            "reject",
            f"discord_notification rejects {binding_reason} context ref={envelope.ref}",
        )
    if _requires_discord_external_collaboration_label(envelope) and not _has_discord_external_collaboration_label(
        envelope
    ):
        return CollaborationSinkDecision(
            "quarantine",
            f"discord_notification requires external collaboration label ref={envelope.ref}",
        )
    if _requires_discord_advisory_label(envelope) and not _has_discord_advisory_label(envelope):
        return CollaborationSinkDecision(
            "quarantine",
            f"discord_notification requires advisory or unverified label ref={envelope.ref}",
        )
    source_refs_decision = _validate_discord_source_refs(
        envelope,
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )
    if source_refs_decision:
        return source_refs_decision
    citations_decision = _validate_discord_citations(
        envelope,
        known_evidence_refs=known_evidence_refs,
        known_rag_refs=known_rag_refs,
    )
    if citations_decision:
        return citations_decision
    return CollaborationSinkDecision("accept")


def _validate_discord_source_refs(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_note_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> CollaborationSinkDecision | None:
    if envelope.kind not in DISCORD_SOURCE_REF_VALIDATED_KINDS:
        return None
    for source_ref_error in source_refs_metadata_errors(envelope):
        return CollaborationSinkDecision(
            "reject",
            f"discord_notification rejects {source_ref_error} ref={envelope.ref}",
        )
    unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
        envelope.ref,
        source_refs_metadata_values(envelope),
        known_evidence_refs=known_evidence_refs,
        known_note_refs=known_note_refs,
        known_rag_refs=known_rag_refs,
    )
    if unresolved_source_refs:
        return CollaborationSinkDecision("reject", "; ".join(unresolved_source_refs))
    return None


def _validate_discord_citations(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> CollaborationSinkDecision | None:
    citations = CitationValidator(
        known_evidence_refs=known_evidence_refs,
        known_rag_refs=known_rag_refs,
    ).validate([envelope])
    if not citations.valid:
        return CollaborationSinkDecision("reject", "; ".join(citations.errors))
    return None


def _validate_github_issue(envelope: ContextEnvelope) -> CollaborationSinkDecision:
    if is_generated_export_context(envelope) or has_generated_export_path(envelope):
        return CollaborationSinkDecision(
            "reject",
            f"github_issue rejects generated export recursion ref={envelope.ref}",
        )
    if _has_evidence_proof_kind(envelope) or _has_truth_like_authority(envelope) or has_context_flag(
        envelope,
        GITHUB_AUTHORITY_FLAGS,
    ):
        return CollaborationSinkDecision("reject", f"github_issue must not create target authority ref={envelope.ref}")
    if _has_target_fact_marker(envelope):
        return CollaborationSinkDecision("reject", f"github_issue must not create target fact ref={envelope.ref}")
    if (_has_evidence_refs(envelope) or has_context_flag(envelope, SENSITIVE_GITHUB_FLAGS)) and not _is_redacted(envelope):
        return CollaborationSinkDecision("reject", f"github_issue requires redacted evidence refs ref={envelope.ref}")
    unsupported_source_types = [
        source_type
        for source_type in [
            normalized_context_key(envelope.source_type),
            *_metadata_text_values(envelope, "source_type"),
        ]
        if source_type and source_type not in GITHUB_ISSUE_SOURCE_TYPES
    ]
    if unsupported_source_types:
        return CollaborationSinkDecision(
            "reject",
            "github_issue rejects unsupported engineering issue "
            f"source_type={unsupported_source_types[0]} ref={envelope.ref}",
        )
    if envelope.kind not in GITHUB_ISSUE_KINDS:
        return CollaborationSinkDecision(
            "reject",
            f"github_issue rejects unsupported engineering issue kind={envelope.kind} ref={envelope.ref}",
        )
    unsupported_context_types = [
        context_type
        for context_type in _metadata_text_values(envelope, "context_type", "context_types")
        if context_type not in GITHUB_ISSUE_CONTEXT_TYPES
    ]
    if unsupported_context_types:
        return CollaborationSinkDecision(
            "reject",
            "github_issue rejects unsupported engineering issue "
            f"context_type={unsupported_context_types[0]} ref={envelope.ref}",
        )
    return CollaborationSinkDecision("accept")


def _requires_discord_advisory_label(envelope: ContextEnvelope) -> bool:
    kinds = {normalized_context_key(envelope.kind), *_metadata_text_values(envelope, "kind", "kinds")}
    authorities = {
        normalized_context_key(envelope.authority),
        *_metadata_text_values(envelope, "authority", "authorities"),
    }
    source_types = {normalized_context_key(envelope.source_type), *_metadata_text_values(envelope, "source_type")}
    return (
        bool(kinds & DISCORD_ADVISORY_KINDS)
        or bool(authorities & {"advisory", "derived"})
        or bool(source_types & ADVISORY_SOURCE_TYPES)
    )


def _requires_discord_external_collaboration_label(envelope: ContextEnvelope) -> bool:
    source_types = {normalized_context_key(envelope.source_type), *_metadata_text_values(envelope, "source_type")}
    return bool(source_types & DISCORD_EXTERNAL_COLLABORATION_SOURCE_TYPES)


def _is_non_evidence_source_proof_record(envelope: ContextEnvelope) -> bool:
    return envelope.kind in EVIDENCE_PROOF_KINDS and envelope.source_type in NON_EVIDENCE_SOURCE_TYPES


def _has_evidence_proof_kind(envelope: ContextEnvelope) -> bool:
    return normalized_context_key(envelope.kind) in EVIDENCE_PROOF_KINDS or bool(
        set(_metadata_text_values(envelope, "kind", "kinds")) & EVIDENCE_PROOF_KINDS
    )


def _is_non_authority_source_authority_record(envelope: ContextEnvelope) -> bool:
    source_types = {normalized_context_key(envelope.source_type), *_metadata_text_values(envelope, "source_type")}
    kinds = {normalized_context_key(envelope.kind), *_metadata_text_values(envelope, "kind", "kinds")}
    authorities = {
        normalized_context_key(envelope.authority),
        *_metadata_text_values(envelope, "authority", "authorities"),
    }
    return bool(source_types & NON_EVIDENCE_SOURCE_TYPES) and (
        bool(kinds & DISCORD_AUTHORITY_KINDS) or bool(authorities & TRUTH_LIKE_AUTHORITIES)
    )


def _has_truth_like_authority(envelope: ContextEnvelope) -> bool:
    return normalized_context_key(envelope.authority) in TRUTH_LIKE_AUTHORITIES or bool(
        set(_metadata_text_values(envelope, "authority", "authorities")) & TRUTH_LIKE_AUTHORITIES
    )


def _has_discord_advisory_label(envelope: ContextEnvelope) -> bool:
    return bool(set(_metadata_labels(envelope)) & DISCORD_ADVISORY_LABELS)


def _has_discord_external_collaboration_label(envelope: ContextEnvelope) -> bool:
    return bool(set(_metadata_labels(envelope)) & DISCORD_EXTERNAL_COLLABORATION_LABELS)


def _metadata_labels(envelope: ContextEnvelope) -> list[str]:
    labels = _metadata_value(envelope, "labels")
    if isinstance(labels, str):
        values = [labels]
    elif isinstance(labels, list | tuple | set):
        values = list(labels)
    else:
        values = []
    values.extend(
        [
            _metadata_value(envelope, "label"),
            _metadata_value(envelope, "authority_label"),
            _metadata_value(envelope, "classification"),
        ]
    )
    return [str(item).strip().lower() for item in values if str(item).strip()]


def _is_redacted(envelope: ContextEnvelope) -> bool:
    return has_context_flag(envelope, REDACTION_FLAGS)


def _has_evidence_refs(envelope: ContextEnvelope) -> bool:
    metadata_refs = [
        ref
        for value in _metadata_values_from(envelope.metadata, "evidence_refs", "evidence_ids")
        for ref in _metadata_ref_values(value)
    ]
    return any(_ref_text(item).startswith("evidence:") for item in [*metadata_refs, *envelope.citations])


def _has_target_fact_marker(envelope: ContextEnvelope) -> bool:
    return has_context_flag(envelope, TARGET_FACT_METADATA_KEYS)


def _metadata_ref_values(value: object) -> list[object]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list | tuple | set):
        return list(value)
    return []


def _metadata_text_values(envelope: ContextEnvelope, *names: str) -> list[str]:
    values: list[str] = []
    for value in _metadata_values_from(envelope.metadata, *names):
        for item in _metadata_ref_values(value):
            text = normalized_context_key(item)
            if text:
                values.append(text)
    return values


def _metadata_values_from(value: object, *names: str) -> list[object]:
    normalized_names = normalized_context_keys(names)
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


def _ref_text(value: object) -> str:
    return str(value).strip()


def _metadata_value(envelope: ContextEnvelope, *names: str) -> object | None:
    normalized_names = normalized_context_keys(names)
    for raw_key, value in envelope.metadata.items():
        if normalized_context_key(raw_key) in normalized_names:
            return value
    return None
