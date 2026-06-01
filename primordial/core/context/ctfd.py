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
    if _has_non_ctfd_source_type(envelope):
        return CtfdSinkDecision(
            "reject",
            f"ctfd_submission accepts only CTFd source material ref={envelope.ref}",
        )
    flag_submission = _is_flag_submission(envelope)
    if flag_submission and not _has_ctf_solve_intent(envelope):
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
    if _has_unsupported_record_type(envelope, SUBMISSION_RECORD_TYPES) or _record_type(envelope) not in SUBMISSION_RECORD_TYPES:
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
    if _has_non_ctfd_source_type(envelope):
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
    if _has_unsupported_record_type(envelope, REGISTRY_RECORD_TYPES) or record_type not in REGISTRY_RECORD_TYPES:
        return CtfdSinkDecision(
            "reject",
            f"ctfd_registry requires challenge or scoreboard record_type ref={envelope.ref}",
        )
    return CtfdSinkDecision("accept")


def _is_flag_submission(envelope: ContextEnvelope) -> bool:
    submission_types = normalized_context_keys(_metadata_values(envelope, "submission_type", "submission_types"))
    return (
        bool(submission_types & FLAG_SUBMISSION_TYPES)
        or has_context_flag(envelope, ("contains_captured_flag", "submits_flag"))
    )


def _has_ctf_solve_intent(envelope: ContextEnvelope) -> bool:
    active_intents = _active_intents(envelope)
    return bool(active_intents) and active_intents <= CTF_SOLVE_INTENTS


def _active_intents(envelope: ContextEnvelope) -> set[str]:
    values: list[object] = []
    for active_intent in _metadata_values(envelope, "active_intent", "active_intents"):
        if isinstance(active_intent, (frozenset, list, set, tuple)):
            values.extend(active_intent)
        elif not isinstance(active_intent, dict):
            values.append(active_intent)
    return normalized_context_keys(values)


def _metadata_value(envelope: ContextEnvelope, *names: str) -> object | None:
    return _metadata_value_from(envelope.metadata, *names)


def _metadata_values(envelope: ContextEnvelope, *names: str) -> list[object]:
    return _metadata_values_from(envelope.metadata, *names)


def _metadata_value_from(value: object, *names: str) -> object | None:
    normalized_names = normalized_context_keys(names)
    if isinstance(value, dict):
        items = value.items()
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            nested = _metadata_value_from(item, *names)
            if nested is not None:
                return nested
        return None
    else:
        return None
    for raw_key, item_value in items:
        if normalized_context_key(raw_key) in normalized_names:
            return item_value
        nested = _metadata_value_from(item_value, *names)
        if nested is not None:
            return nested
    return None


def _metadata_values_from(value: object, *names: str) -> list[object]:
    normalized_names = normalized_context_keys(names)
    values: list[object] = []
    if isinstance(value, dict):
        items = value.items()
    elif isinstance(value, (list, tuple, set)):
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


def _authority_mutation_reason(envelope: ContextEnvelope) -> str:
    kind_reason = AUTHORITY_KIND_REASONS.get(envelope.kind)
    if kind_reason:
        return kind_reason
    metadata_kind_reason = _metadata_authority_kind_reason(envelope)
    if metadata_kind_reason:
        return metadata_kind_reason
    for flag, reason in AUTHORITY_MUTATION_REASONS:
        if has_context_flag(envelope, (flag,)):
            return reason
    return ""


def _metadata_authority_kind_reason(envelope: ContextEnvelope) -> str:
    for kind in _metadata_kinds(envelope):
        reason = AUTHORITY_KIND_REASONS.get(kind)
        if reason:
            return reason
    return ""


def _metadata_kinds(envelope: ContextEnvelope) -> list[str]:
    values: list[object] = []
    for kind in _metadata_values(envelope, "kind", "kinds"):
        if isinstance(kind, (frozenset, list, set, tuple)):
            values.extend(kind)
        elif not isinstance(kind, dict):
            values.append(kind)
    return sorted(normalized_context_keys(values))


def _has_target_fact_marker(envelope: ContextEnvelope) -> bool:
    return has_context_flag(envelope, TARGET_FACT_METADATA_KEYS)


def _has_truth_like_authority(envelope: ContextEnvelope) -> bool:
    return (
        normalized_context_key(envelope.authority) in TRUTH_LIKE_AUTHORITIES
        or bool(_metadata_authorities(envelope) & TRUTH_LIKE_AUTHORITIES)
    )


def _metadata_authorities(envelope: ContextEnvelope) -> set[str]:
    values: list[object] = []
    for authority in _metadata_values(envelope, "authority", "authorities"):
        if isinstance(authority, (frozenset, list, set, tuple)):
            values.extend(authority)
        elif not isinstance(authority, dict):
            values.append(authority)
    return normalized_context_keys(values)


def _has_non_ctfd_source_type(envelope: ContextEnvelope) -> bool:
    return bool(_source_types(envelope) - {"ctfd"})


def _source_types(envelope: ContextEnvelope) -> set[str]:
    values: list[object] = [envelope.source_type]
    for source_type in _metadata_values(envelope, "source_type", "source_types"):
        if isinstance(source_type, (frozenset, list, set, tuple)):
            values.extend(source_type)
        elif not isinstance(source_type, dict):
            values.append(source_type)
    return normalized_context_keys(values)


def _has_non_ctfd_citation_support(envelope: ContextEnvelope) -> bool:
    return any(
        bool(citation_ref) and not citation_ref.startswith(CTFD_CITATION_PREFIX)
        for citation_ref in _citation_refs(envelope)
    )


def _citation_refs(envelope: ContextEnvelope) -> list[str]:
    values: list[object] = list(envelope.citations)
    for citations in _metadata_values(envelope, "citation", "citation_ref", "citations", "citation_refs"):
        if isinstance(citations, (frozenset, list, set, tuple)):
            values.extend(citations)
        elif not isinstance(citations, dict):
            values.append(citations)
    return [str(citation).strip().lower() for citation in values]


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


def _has_unsupported_record_type(envelope: ContextEnvelope, allowed_record_types: frozenset[str]) -> bool:
    return bool(_record_types(envelope) - allowed_record_types)


def _record_types(envelope: ContextEnvelope) -> set[str]:
    values: list[object] = []
    for record_type in _metadata_values(envelope, "record_type", "record_types", "projection_type", "projection_types"):
        if isinstance(record_type, (frozenset, list, set, tuple)):
            values.extend(record_type)
        elif not isinstance(record_type, dict):
            values.append(record_type)
    return normalized_context_keys(values)
