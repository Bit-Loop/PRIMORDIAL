from __future__ import annotations

from typing import Iterable

from primordial.core.context.generated_exports import is_generated_export_context
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys
from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.poison import has_context_flag


EVIDENCE_REF_PREFIX = "evidence:"
POLICY_DECISION_REF_PREFIX = "policy_decision:"
PROFILE_PERMISSION_SOURCES = frozenset({"engagement_profile", "profile_label", "scope_profile"})
WRITEUP_AUTHORITY_SOURCES = frozenset({"writeup"})
GENERATED_EXPORT_AUTHORITY_SOURCES = frozenset({"generated_export", "export_archive"})
CTFD_AUTHORITY_SOURCES = frozenset({"ctfd"})
COLLABORATION_AUTHORITY_SOURCES = frozenset({"github", "github_project_context", "engineering_context", "notion"})
ADVISORY_PERMISSION_SOURCES = frozenset(
    {"rag", "ai_output", "chat", "vuln_intel", "methodology_doc", "model", "model_summary"}
)
RECON_ONLY_FORBIDDEN_TASK_SOURCE_TYPES = frozenset({"vuln_intel"})
FALSEY_SCOPE_VALUES = frozenset({"0", "false", "no", "off"})
OUT_OF_SCOPE_STATUSES = frozenset({"out_of_scope", "out_of_scope_explicit", "excluded", "not_in_scope", "denied"})
IN_SCOPE_METADATA_KEYS = ("in_scope", "target_in_scope", "scope_in_scope")
SCOPE_STATUS_METADATA_KEYS = ("scope_status", "target_scope_status", "scope_state")
CURRENT_GENERATION_METADATA_KEYS = (
    "current_active_generation_id",
    "target_active_generation_id",
    "current_generation_id",
    "current_active_ip_generation",
)
TASK_GENERATION_METADATA_KEYS = ("active_generation_id", "generation_id", "active_ip_generation")
CURRENT_TARGET_METADATA_KEYS = (
    "current_target_id",
    "active_target_id",
    "target_context_id",
    "current_scope_target_id",
)
TASK_TARGET_METADATA_KEYS = ("target_id", "task_target_id", "scope_target_id")
EXECUTABLE_ACTION_CLASSES = frozenset(
    {
        "exploit_validation",
        "exploit_execution",
        "poc_applicability_validation",
        "credential_validation",
        "credentialed_access_check",
        "kerberos_attack_check",
        "flag_collection",
        "tool_execution",
    }
)
RECON_ONLY_FORBIDDEN_ACTION_CLASSES = frozenset(
    {
        "exploit_validation",
        "exploit_execution",
        "poc_applicability_validation",
        "credential_validation",
        "credentialed_access_check",
        "kerberos_attack_check",
        "flag_collection",
    }
)


def task_metadata_errors(
    envelope: ContextEnvelope,
    *,
    known_evidence_refs: Iterable[str] | None = None,
) -> list[str]:
    metadata = envelope.metadata
    errors: list[str] = []
    executable = _is_executable_task_metadata(envelope)
    action_class = _action_class(envelope)
    supporting_refs = _supporting_refs(metadata)
    supporting_evidence_refs = [ref for ref in supporting_refs if ref.startswith(EVIDENCE_REF_PREFIX)]
    non_evidence_supporting_refs = [ref for ref in supporting_refs if not ref.startswith(EVIDENCE_REF_PREFIX)]
    uncited_supporting_refs = _uncited_refs(envelope, supporting_evidence_refs)
    unresolved_supporting_refs = _unresolved_refs(supporting_evidence_refs, known_evidence_refs)
    active_intent = normalized_context_key(_metadata_value(metadata, "active_intent"))
    if executable and not active_intent:
        errors.append(f"task_metadata requires active Operator Intent for executable task ref={envelope.ref}")
    if executable and not _task_target(envelope):
        errors.append(f"task_metadata requires target binding for executable task ref={envelope.ref}")
    if executable and not _task_generation(envelope):
        errors.append(f"task_metadata requires active generation binding for executable task ref={envelope.ref}")
    if executable and not _has_citation_prefix(envelope, POLICY_DECISION_REF_PREFIX):
        errors.append(f"task_metadata requires policy_decision:<id> citation for executable task ref={envelope.ref}")
    if executable and uncited_supporting_refs:
        refs = ", ".join(uncited_supporting_refs)
        errors.append(f"task_metadata requires supporting evidence refs to be cited ref={envelope.ref}: {refs}")
    if executable and unresolved_supporting_refs:
        refs = ", ".join(unresolved_supporting_refs)
        errors.append(f"task_metadata rejects unresolved supporting evidence refs ref={envelope.ref}: {refs}")
    if executable and supporting_evidence_refs and known_evidence_refs is None:
        errors.append(f"task_metadata requires known evidence refs for executable task ref={envelope.ref}")
    if executable and non_evidence_supporting_refs:
        refs = ", ".join(non_evidence_supporting_refs)
        errors.append(f"task_metadata rejects non-evidence supporting refs ref={envelope.ref}: {refs}")
    if executable and _has_profile_permission_source(envelope):
        errors.append(f"task_metadata rejects profile label as executable permission ref={envelope.ref}")
    if executable and _has_writeup_action_authority(envelope):
        errors.append(f"task_metadata rejects writeup-derived action authority ref={envelope.ref}")
    if executable and _has_generated_export_action_authority(envelope):
        errors.append(f"task_metadata rejects generated export executable task authority ref={envelope.ref}")
    if executable and _has_ctfd_action_authority(envelope):
        errors.append(f"task_metadata rejects ctfd executable task authority ref={envelope.ref}")
    if executable and _has_collaboration_action_authority(envelope):
        errors.append(f"task_metadata rejects collaboration executable task authority ref={envelope.ref}")
    if executable and _has_advisory_permission_source(envelope):
        errors.append(f"task_metadata rejects advisory executable permission source ref={envelope.ref}")
    if executable and _is_out_of_scope(envelope):
        errors.append(f"task_metadata rejects out-of-scope executable task ref={envelope.ref}")
    if executable and _is_stale_generation(envelope):
        errors.append(f"task_metadata rejects stale generation executable task ref={envelope.ref}")
    if executable and _is_wrong_target(envelope):
        errors.append(f"task_metadata rejects wrong target executable task ref={envelope.ref}")
    if executable and active_intent == "recon_only" and action_class in RECON_ONLY_FORBIDDEN_ACTION_CLASSES:
        errors.append(f"task_metadata rejects {action_class} under recon_only ref={envelope.ref}")
    if (
        executable
        and not _cited_supporting_evidence_refs(envelope, supporting_evidence_refs)
    ):
        errors.append(f"task_metadata requires cited supporting target evidence for executable task ref={envelope.ref}")
    if executable and active_intent == "recon_only" and envelope.source_type in RECON_ONLY_FORBIDDEN_TASK_SOURCE_TYPES:
        errors.append(f"task_metadata rejects {envelope.source_type} executable action under recon_only ref={envelope.ref}")
    return errors


def _has_profile_permission_source(envelope: ContextEnvelope) -> bool:
    source = _authority_source(envelope)
    return (
        envelope.source_type in PROFILE_PERMISSION_SOURCES
        or source in PROFILE_PERMISSION_SOURCES
        or has_context_flag(envelope, ("profile_authorizes_action",))
    )


def _has_writeup_action_authority(envelope: ContextEnvelope) -> bool:
    return (
        envelope.source_type in WRITEUP_AUTHORITY_SOURCES
        or _authority_source(envelope) in WRITEUP_AUTHORITY_SOURCES
        or has_context_flag(
            envelope,
            ("writeup_authorizes_action",),
        )
    )


def _has_generated_export_action_authority(envelope: ContextEnvelope) -> bool:
    return (
        is_generated_export_context(envelope)
        or _authority_source(envelope) in GENERATED_EXPORT_AUTHORITY_SOURCES
    )


def _has_ctfd_action_authority(envelope: ContextEnvelope) -> bool:
    return envelope.source_type in CTFD_AUTHORITY_SOURCES or _authority_source(envelope) in CTFD_AUTHORITY_SOURCES


def _has_collaboration_action_authority(envelope: ContextEnvelope) -> bool:
    return envelope.source_type in COLLABORATION_AUTHORITY_SOURCES or _authority_source(
        envelope
    ) in COLLABORATION_AUTHORITY_SOURCES


def _has_advisory_permission_source(envelope: ContextEnvelope) -> bool:
    return (
        envelope.source_type in ADVISORY_PERMISSION_SOURCES
        or _authority_source(envelope) in ADVISORY_PERMISSION_SOURCES
    )


def _is_out_of_scope(envelope: ContextEnvelope) -> bool:
    scope_value = _first_metadata_key_value(envelope.metadata, IN_SCOPE_METADATA_KEYS)
    if scope_value and normalized_context_key(scope_value) in FALSEY_SCOPE_VALUES:
        return True
    status = _first_metadata_key_value(envelope.metadata, SCOPE_STATUS_METADATA_KEYS)
    return normalized_context_key(status) in OUT_OF_SCOPE_STATUSES


def _authority_source(envelope: ContextEnvelope) -> str:
    metadata = envelope.metadata
    return normalized_context_key(
        _metadata_value(
            metadata,
            "permission_source",
            "authorization_source",
            "permission_basis",
            "authority_source",
            "task_authority_source",
        )
        or ""
    )


def _is_executable_task_metadata(envelope: ContextEnvelope) -> bool:
    if has_context_flag(envelope, ("creates_executable_task",)):
        return True
    return _action_class(envelope) in EXECUTABLE_ACTION_CLASSES


def _action_class(envelope: ContextEnvelope) -> str:
    return normalized_context_key(_metadata_value(envelope.metadata, "action_class", "task_kind"))


def _is_stale_generation(envelope: ContextEnvelope) -> bool:
    task_generation = _task_generation(envelope)
    current_generation = _first_metadata_value(envelope.metadata, CURRENT_GENERATION_METADATA_KEYS)
    return bool(task_generation and current_generation and task_generation != current_generation)


def _is_wrong_target(envelope: ContextEnvelope) -> bool:
    task_target = _task_target(envelope)
    current_target = _first_metadata_identifier(envelope.metadata, CURRENT_TARGET_METADATA_KEYS)
    return bool(task_target and current_target and task_target != current_target)


def _task_target(envelope: ContextEnvelope) -> str:
    return _identifier_value(envelope.target_id) or _first_metadata_identifier(
        envelope.metadata,
        TASK_TARGET_METADATA_KEYS,
    )


def _task_generation(envelope: ContextEnvelope) -> str:
    return _generation_value(envelope.active_generation_id) or _first_metadata_value(
        envelope.metadata,
        TASK_GENERATION_METADATA_KEYS,
    )


def _first_metadata_value(metadata: dict[str, object], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = _generation_value(_metadata_value(metadata, key))
        if value:
            return value
    return ""


def _first_metadata_key_value(metadata: dict[str, object], keys: tuple[str, ...]) -> object | None:
    for key in keys:
        value = _metadata_value(metadata, key)
        if value is not None:
            return value
    return None


def _generation_value(value: object) -> str:
    return str(value or "").strip().lower()


def _first_metadata_identifier(metadata: dict[str, object], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = _identifier_value(_metadata_value(metadata, key))
        if value:
            return value
    return ""


def _identifier_value(value: object) -> str:
    return str(value or "").strip().lower()


def _supporting_refs(metadata: dict[str, object]) -> list[str]:
    refs = _metadata_value(metadata, "supporting_evidence_refs", "evidence_refs")
    if isinstance(refs, str):
        values = [refs]
    elif isinstance(refs, list):
        values = refs
    else:
        return []
    return [str(item).strip() for item in values if str(item).strip()]


def _metadata_value(metadata: dict[str, object], *names: str) -> object | None:
    normalized_names = normalized_context_keys(names)
    for raw_key, value in metadata.items():
        if normalized_context_key(raw_key) in normalized_names:
            return value
    return None


def _cited_supporting_evidence_refs(envelope: ContextEnvelope, refs: list[str]) -> list[str]:
    citation_refs = {str(item).strip() for item in envelope.citations}
    return [ref for ref in refs if ref in citation_refs]


def _uncited_refs(envelope: ContextEnvelope, refs: list[str]) -> list[str]:
    citation_refs = {str(item).strip() for item in envelope.citations}
    return [ref for ref in refs if ref not in citation_refs]


def _unresolved_refs(refs: list[str], known_refs: Iterable[str] | None) -> list[str]:
    if known_refs is None:
        return []
    normalized_known_refs = {str(ref).strip() for ref in known_refs if str(ref).strip()}
    return [ref for ref in refs if ref not in normalized_known_refs]


def _has_citation_prefix(envelope: ContextEnvelope, prefix: str) -> bool:
    return any(str(item).startswith(prefix) for item in envelope.citations)
