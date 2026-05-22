from __future__ import annotations

from dataclasses import dataclass

from primordial.core.context.bindings import TARGET_FACT_METADATA_KEYS
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys
from primordial.core.context.poison import has_context_flag
from primordial.core.context.source_refs import has_malformed_source_refs_metadata, source_refs_metadata_values
from primordial.core.context.source_types import TRUTH_LIKE_AUTHORITIES


CTF_SOLVE_INTENTS = frozenset({"ctf_solve_assisted", "ctf_solve_autonomous_local"})
FLAG_SUBMISSION_TYPES = frozenset({"flag", "flag_submission", "captured_flag"})
SUBMISSION_KINDS = frozenset({"ctfd_ref", "ctfd_submission", "scoreboard_projection", "submission_result"})
SUBMISSION_RECORD_TYPES = frozenset({"scoreboard", "scoreboard_projection", "submission_result"})
REGISTRY_KINDS = frozenset({"ctfd_ref", "challenge_metadata", "scoreboard_projection", "solve_status"})
REGISTRY_RECORD_TYPES = frozenset({
    "challenge_metadata",
    "scoreboard_projection",
    "solve_status",
    "submission_result",
})
HIDDEN_FLAG_FLAGS = (
    "contains_raw_expected_flag",
    "contains_raw_flag",
    "hidden_solution_material",
    "contains_secret",
    "expected_flag_visible",
)
AUTHORITY_FLAGS = (
    "creates_evidence",
    "creates_target_authority",
    "mutates_target_truth",
    "authorizes_target_action",
    "changes_scope",
    "changes_operator_intent",
    "creates_approval",
)
AUTHORITY_MUTATION_REASONS = (
    ("creates_evidence", "evidence"),
    ("creates_approval", "approval"),
    ("changes_scope", "scope"),
    ("changes_operator_intent", "Operator Intent"),
    ("creates_target_authority", "target authority"),
    ("mutates_target_truth", "target authority"),
    ("authorizes_target_action", "target action"),
)
AUTHORITY_KIND_REASONS = {
    "authority": "authority",
    "evidence": "evidence",
    "approval": "approval",
    "scope": "scope",
    "operator_intent": "Operator Intent",
    "policy_decision": "policy decision",
    "finding": "target finding",
}
CTFD_CITATION_PREFIX = "ctfd:"


@dataclass(frozen=True, slots=True)
class CtfdSinkDecision:
    action: str
    message: str = ""


def validate_ctfd_submission_sink(envelope: ContextEnvelope) -> CtfdSinkDecision:
    if has_context_flag(envelope, HIDDEN_FLAG_FLAGS):
        return CtfdSinkDecision(
            "reject",
            f"ctfd_submission must not expose hidden or raw flag material ref={envelope.ref}",
        )
    authority_reason = _authority_mutation_reason(envelope)
    if authority_reason:
        return CtfdSinkDecision("reject", f"ctfd_submission must not create {authority_reason} ref={envelope.ref}")
    if _has_target_fact_marker(envelope):
        return CtfdSinkDecision("reject", f"ctfd_submission must not create target fact ref={envelope.ref}")
    if _has_truth_like_authority(envelope):
        return CtfdSinkDecision(
            "reject",
            f"ctfd_submission rejects {envelope.ref}: CTFd material cannot carry truth-like authority",
        )
    if envelope.source_type != "ctfd":
        return CtfdSinkDecision(
            "reject",
            f"ctfd_submission accepts only CTFd source material ref={envelope.ref}",
        )
    flag_submission = _is_flag_submission(envelope)
    if flag_submission and _active_intent(envelope) not in CTF_SOLVE_INTENTS:
        return CtfdSinkDecision("reject", f"ctfd_submission requires ctf solve intent ref={envelope.ref}")
    if _has_non_ctfd_citation_support(envelope):
        return CtfdSinkDecision(
            "reject",
            f"ctfd_submission rejects non-CTFd citation support ref={envelope.ref}",
        )
    if has_malformed_source_refs_metadata(envelope):
        return CtfdSinkDecision("reject", f"ctfd_submission rejects malformed source_refs ref={envelope.ref}")
    non_ctfd_source_refs = _non_ctfd_source_refs(envelope)
    if non_ctfd_source_refs:
        return CtfdSinkDecision(
            "reject",
            f"ctfd_submission rejects non-CTFd source_refs ref={envelope.ref}: {', '.join(non_ctfd_source_refs)}",
        )
    if flag_submission:
        return CtfdSinkDecision("accept")
    if envelope.kind not in SUBMISSION_KINDS:
        return CtfdSinkDecision(
            "reject",
            f"ctfd_submission accepts only submission result material kind={envelope.kind} ref={envelope.ref}",
        )
    if _record_type(envelope) not in SUBMISSION_RECORD_TYPES:
        return CtfdSinkDecision(
            "reject",
            f"ctfd_submission requires submission_result record_type or scoreboard projection ref={envelope.ref}",
        )
    return CtfdSinkDecision("accept")


def validate_ctfd_registry_sink(envelope: ContextEnvelope) -> CtfdSinkDecision:
    if has_context_flag(envelope, HIDDEN_FLAG_FLAGS):
        return CtfdSinkDecision(
            "reject",
            f"ctfd_registry must not expose hidden or raw flag material ref={envelope.ref}",
        )
    authority_reason = _authority_mutation_reason(envelope)
    if authority_reason:
        return CtfdSinkDecision(
            "reject",
            f"ctfd_registry must not create {authority_reason} ref={envelope.ref}",
        )
    if _has_target_fact_marker(envelope):
        return CtfdSinkDecision("reject", f"ctfd_registry must not create target fact ref={envelope.ref}")
    if _has_truth_like_authority(envelope):
        return CtfdSinkDecision(
            "reject",
            f"ctfd_registry rejects {envelope.ref}: CTFd material cannot carry truth-like authority",
        )
    if envelope.source_type != "ctfd":
        return CtfdSinkDecision(
            "reject",
            f"ctfd_registry accepts only CTFd source material ref={envelope.ref}",
        )
    if _has_non_ctfd_citation_support(envelope):
        return CtfdSinkDecision(
            "reject",
            f"ctfd_registry rejects non-CTFd citation support ref={envelope.ref}",
        )
    if has_malformed_source_refs_metadata(envelope):
        return CtfdSinkDecision("reject", f"ctfd_registry rejects malformed source_refs ref={envelope.ref}")
    non_ctfd_source_refs = _non_ctfd_source_refs(envelope)
    if non_ctfd_source_refs:
        return CtfdSinkDecision(
            "reject",
            f"ctfd_registry rejects non-CTFd source_refs ref={envelope.ref}: {', '.join(non_ctfd_source_refs)}",
        )
    if envelope.kind not in REGISTRY_KINDS:
        return CtfdSinkDecision(
            "reject",
            f"ctfd_registry accepts only challenge and scoreboard metadata kind={envelope.kind} ref={envelope.ref}",
        )
    record_type = _record_type(envelope)
    if record_type not in REGISTRY_RECORD_TYPES:
        return CtfdSinkDecision(
            "reject",
            f"ctfd_registry requires challenge or scoreboard record_type ref={envelope.ref}",
        )
    return CtfdSinkDecision("accept")


def _is_flag_submission(envelope: ContextEnvelope) -> bool:
    submission_type = normalized_context_key(_metadata_value(envelope, "submission_type"))
    return (
        submission_type in FLAG_SUBMISSION_TYPES
        or has_context_flag(envelope, ("contains_captured_flag", "submits_flag"))
    )


def _active_intent(envelope: ContextEnvelope) -> str:
    return normalized_context_key(_metadata_value(envelope, "active_intent"))


def _metadata_value(envelope: ContextEnvelope, *names: str) -> object | None:
    normalized_names = normalized_context_keys(names)
    for raw_key, value in envelope.metadata.items():
        if normalized_context_key(raw_key) in normalized_names:
            return value
    return None


def _authority_mutation_reason(envelope: ContextEnvelope) -> str:
    kind_reason = AUTHORITY_KIND_REASONS.get(envelope.kind)
    if kind_reason:
        return kind_reason
    for flag, reason in AUTHORITY_MUTATION_REASONS:
        if has_context_flag(envelope, (flag,)):
            return reason
    return ""


def _has_target_fact_marker(envelope: ContextEnvelope) -> bool:
    return has_context_flag(envelope, TARGET_FACT_METADATA_KEYS)


def _has_truth_like_authority(envelope: ContextEnvelope) -> bool:
    return normalized_context_key(envelope.authority) in TRUTH_LIKE_AUTHORITIES


def _has_non_ctfd_citation_support(envelope: ContextEnvelope) -> bool:
    return any(
        bool(citation_ref) and not citation_ref.startswith(CTFD_CITATION_PREFIX)
        for citation_ref in (str(citation).strip().lower() for citation in envelope.citations)
    )


def _non_ctfd_source_refs(envelope: ContextEnvelope) -> list[str]:
    return sorted(
        {
            source_ref
            for source_ref in (str(ref).strip() for ref in source_refs_metadata_values(envelope))
            if source_ref and not source_ref.lower().startswith(CTFD_CITATION_PREFIX)
        }
    )


def _record_type(envelope: ContextEnvelope) -> str:
    return str(
        envelope.metadata.get("record_type")
        or envelope.metadata.get("projection_type")
        or envelope.kind
        or ""
    ).strip().lower()
