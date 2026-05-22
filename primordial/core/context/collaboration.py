from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from primordial.core.context.bindings import TARGET_FACT_METADATA_KEYS, current_context_binding_error
from primordial.core.context.citations import CitationValidator
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.generated_exports import is_generated_export_context
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys
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


ADVISORY_SOURCE_TYPES = frozenset({"vuln_intel", "methodology_doc", "writeup", "ai_output", "chat"})
AI_SUMMARY_KINDS = frozenset({"model_summary", "hypothesis", "candidate_task"})
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
    known_rag_refs: Iterable[str] | None = None,
) -> CollaborationSinkDecision:
    normalized_sink = str(sink or "").strip().lower()
    if normalized_sink == "discord_notification":
        return _validate_discord_notification(
            envelope,
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        )
    if normalized_sink == "github_issue":
        return _validate_github_issue(envelope)
    return CollaborationSinkDecision("accept")


def _validate_discord_notification(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None,
    known_rag_refs: Iterable[str] | None,
) -> CollaborationSinkDecision:
    if is_generated_export_context(envelope):
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
    if envelope.kind in AI_SUMMARY_KINDS and envelope.authority in TRUTH_LIKE_AUTHORITIES:
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
    if envelope.kind in AI_SUMMARY_KINDS:
        for source_ref_error in source_refs_metadata_errors(envelope):
            return CollaborationSinkDecision(
                "reject",
                f"discord_notification rejects {source_ref_error} ref={envelope.ref}",
            )
        unresolved_source_refs = unresolved_ai_derived_source_ref_errors(
            envelope.ref,
            source_refs_metadata_values(envelope),
            known_evidence_refs=known_evidence_refs,
            known_rag_refs=known_rag_refs,
        )
        if unresolved_source_refs:
            return CollaborationSinkDecision("reject", "; ".join(unresolved_source_refs))
    citations = CitationValidator(
        known_evidence_refs=known_evidence_refs,
        known_rag_refs=known_rag_refs,
    ).validate([envelope])
    if not citations.valid:
        return CollaborationSinkDecision("reject", "; ".join(citations.errors))
    return CollaborationSinkDecision("accept")


def _validate_github_issue(envelope: ContextEnvelope) -> CollaborationSinkDecision:
    if is_generated_export_context(envelope):
        return CollaborationSinkDecision(
            "reject",
            f"github_issue rejects generated export recursion ref={envelope.ref}",
        )
    if envelope.kind in EVIDENCE_PROOF_KINDS or envelope.authority in TRUTH_LIKE_AUTHORITIES or has_context_flag(
        envelope,
        GITHUB_AUTHORITY_FLAGS,
    ):
        return CollaborationSinkDecision("reject", f"github_issue must not create target authority ref={envelope.ref}")
    if _has_target_fact_marker(envelope):
        return CollaborationSinkDecision("reject", f"github_issue must not create target fact ref={envelope.ref}")
    if (_has_evidence_refs(envelope) or has_context_flag(envelope, SENSITIVE_GITHUB_FLAGS)) and not _is_redacted(envelope):
        return CollaborationSinkDecision("reject", f"github_issue requires redacted evidence refs ref={envelope.ref}")
    if envelope.source_type not in GITHUB_ISSUE_SOURCE_TYPES:
        return CollaborationSinkDecision(
            "reject",
            f"github_issue rejects unsupported engineering issue source_type={envelope.source_type} ref={envelope.ref}",
        )
    if envelope.kind not in GITHUB_ISSUE_KINDS:
        return CollaborationSinkDecision(
            "reject",
            f"github_issue rejects unsupported engineering issue kind={envelope.kind} ref={envelope.ref}",
        )
    context_type = _github_issue_context_type(envelope)
    if context_type and context_type not in GITHUB_ISSUE_CONTEXT_TYPES:
        return CollaborationSinkDecision(
            "reject",
            f"github_issue rejects unsupported engineering issue context_type={context_type} ref={envelope.ref}",
        )
    return CollaborationSinkDecision("accept")


def _requires_discord_advisory_label(envelope: ContextEnvelope) -> bool:
    return (
        envelope.kind in DISCORD_ADVISORY_KINDS
        or envelope.authority in {"advisory", "derived"}
        or envelope.source_type in ADVISORY_SOURCE_TYPES
    )


def _requires_discord_external_collaboration_label(envelope: ContextEnvelope) -> bool:
    return envelope.source_type in DISCORD_EXTERNAL_COLLABORATION_SOURCE_TYPES


def _is_non_evidence_source_proof_record(envelope: ContextEnvelope) -> bool:
    return envelope.kind in EVIDENCE_PROOF_KINDS and envelope.source_type in NON_EVIDENCE_SOURCE_TYPES


def _is_non_authority_source_authority_record(envelope: ContextEnvelope) -> bool:
    return envelope.source_type in NON_EVIDENCE_SOURCE_TYPES and (
        envelope.kind in DISCORD_AUTHORITY_KINDS or envelope.authority in TRUTH_LIKE_AUTHORITIES
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
    refs = _metadata_value(envelope, "evidence_refs")
    metadata_refs = _metadata_ref_values(refs)
    return any(_ref_text(item).startswith("evidence:") for item in [*metadata_refs, *envelope.citations])


def _github_issue_context_type(envelope: ContextEnvelope) -> str:
    value = _metadata_value(envelope, "context_type")
    return normalized_context_key(value)


def _has_target_fact_marker(envelope: ContextEnvelope) -> bool:
    return has_context_flag(envelope, TARGET_FACT_METADATA_KEYS)


def _metadata_ref_values(value: object) -> list[object]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list | tuple | set):
        return list(value)
    return []


def _ref_text(value: object) -> str:
    return str(value).strip()


def _metadata_value(envelope: ContextEnvelope, *names: str) -> object | None:
    normalized_names = normalized_context_keys(names)
    for raw_key, value in envelope.metadata.items():
        if normalized_context_key(raw_key) in normalized_names:
            return value
    return None
