from __future__ import annotations

from typing import Iterable

from primordial.core.context.generated_exports import has_generated_export_path, is_generated_export_context
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
IN_SCOPE_METADATA_KEYS = (
    "in_scope",
    "in_scopes",
    "target_in_scope",
    "target_in_scopes",
    "scope_in_scope",
    "scope_in_scopes",
)
SCOPE_STATUS_METADATA_KEYS = (
    "scope_status",
    "scope_statuses",
    "target_scope_status",
    "target_scope_statuses",
    "scope_state",
    "scope_states",
)
CURRENT_GENERATION_METADATA_KEYS = (
    "current_active_generation_id",
    "current_active_generation_ids",
    "target_active_generation_id",
    "target_active_generation_ids",
    "current_generation_id",
    "current_generation_ids",
    "current_active_ip_generation",
    "current_active_ip_generations",
)
TASK_GENERATION_METADATA_KEYS = (
    "active_generation_id",
    "active_generation_ids",
    "generation_id",
    "generation_ids",
    "active_ip_generation",
    "active_ip_generations",
)
CURRENT_TARGET_METADATA_KEYS = (
    "current_target_id",
    "current_target_ids",
    "active_target_id",
    "active_target_ids",
    "target_context_id",
    "target_context_ids",
    "current_scope_target_id",
    "current_scope_target_ids",
)
TASK_TARGET_METADATA_KEYS = (
    "target_id",
    "target_ids",
    "task_target_id",
    "task_target_ids",
    "scope_target_id",
    "scope_target_ids",
)
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
    action_classes = _action_classes(envelope)
    supporting_refs = _supporting_refs(metadata)
    supporting_evidence_refs = [ref for ref in supporting_refs if ref.startswith(EVIDENCE_REF_PREFIX)]
    non_evidence_supporting_refs = [ref for ref in supporting_refs if not ref.startswith(EVIDENCE_REF_PREFIX)]
    uncited_supporting_refs = _uncited_refs(envelope, supporting_evidence_refs)
    unresolved_supporting_refs = _unresolved_refs(supporting_evidence_refs, known_evidence_refs)
    active_intents = _active_intents(metadata)
    if executable and not active_intents:
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
    if executable and "recon_only" in active_intents:
        for forbidden_action_class in sorted(action_classes & RECON_ONLY_FORBIDDEN_ACTION_CLASSES):
            errors.append(f"task_metadata rejects {forbidden_action_class} under recon_only ref={envelope.ref}")
    if (
        executable
        and not _cited_supporting_evidence_refs(envelope, supporting_evidence_refs)
    ):
        errors.append(f"task_metadata requires cited supporting target evidence for executable task ref={envelope.ref}")
    if executable and "recon_only" in active_intents:
        for forbidden_source_type in sorted(_recon_only_forbidden_task_source_types(envelope)):
            errors.append(
                f"task_metadata rejects {forbidden_source_type} executable action under recon_only ref={envelope.ref}"
            )
    return errors


def _has_profile_permission_source(envelope: ContextEnvelope) -> bool:
    sources = _authority_sources(envelope)
    return (
        envelope.source_type in PROFILE_PERMISSION_SOURCES
        or bool(_metadata_source_types(envelope) & PROFILE_PERMISSION_SOURCES)
        or bool(sources & PROFILE_PERMISSION_SOURCES)
        or has_context_flag(envelope, ("profile_authorizes_action",))
    )


def _has_writeup_action_authority(envelope: ContextEnvelope) -> bool:
    return (
        envelope.source_type in WRITEUP_AUTHORITY_SOURCES
        or bool(_metadata_source_types(envelope) & WRITEUP_AUTHORITY_SOURCES)
        or bool(_authority_sources(envelope) & WRITEUP_AUTHORITY_SOURCES)
        or has_context_flag(
            envelope,
            ("writeup_authorizes_action",),
        )
    )


def _has_generated_export_action_authority(envelope: ContextEnvelope) -> bool:
    return (
        is_generated_export_context(envelope)
        or _has_generated_export_path(envelope)
        or bool(_authority_sources(envelope) & GENERATED_EXPORT_AUTHORITY_SOURCES)
    )


def _has_ctfd_action_authority(envelope: ContextEnvelope) -> bool:
    return (
        envelope.source_type in CTFD_AUTHORITY_SOURCES
        or bool(_metadata_source_types(envelope) & CTFD_AUTHORITY_SOURCES)
        or bool(_authority_sources(envelope) & CTFD_AUTHORITY_SOURCES)
    )


def _has_collaboration_action_authority(envelope: ContextEnvelope) -> bool:
    return (
        envelope.source_type in COLLABORATION_AUTHORITY_SOURCES
        or bool(_metadata_source_types(envelope) & COLLABORATION_AUTHORITY_SOURCES)
        or bool(_authority_sources(envelope) & COLLABORATION_AUTHORITY_SOURCES)
    )


def _has_advisory_permission_source(envelope: ContextEnvelope) -> bool:
    return (
        envelope.source_type in ADVISORY_PERMISSION_SOURCES
        or bool(_metadata_source_types(envelope) & ADVISORY_PERMISSION_SOURCES)
        or bool(_authority_sources(envelope) & ADVISORY_PERMISSION_SOURCES)
    )


def _recon_only_forbidden_task_source_types(envelope: ContextEnvelope) -> set[str]:
    sources = {normalized_context_key(envelope.source_type)} | _metadata_source_types(envelope)
    return sources & RECON_ONLY_FORBIDDEN_TASK_SOURCE_TYPES


def _active_intents(metadata: object) -> set[str]:
    values: list[object] = []
    for active_intent in _metadata_values(metadata, "active_intent", "active_intents"):
        values.extend(_metadata_scalar_values(active_intent))
    return normalized_context_keys(values)


def _is_out_of_scope(envelope: ContextEnvelope) -> bool:
    scope_values = _normalized_metadata_values(envelope.metadata, *IN_SCOPE_METADATA_KEYS)
    if scope_values & FALSEY_SCOPE_VALUES:
        return True
    statuses = _normalized_metadata_values(envelope.metadata, *SCOPE_STATUS_METADATA_KEYS)
    return bool(statuses & OUT_OF_SCOPE_STATUSES)


def _authority_sources(envelope: ContextEnvelope) -> set[str]:
    return _normalized_metadata_values(
        envelope.metadata,
        "permission_source",
        "permission_sources",
        "authorization_source",
        "authorization_sources",
        "permission_basis",
        "permission_bases",
        "authority_source",
        "authority_sources",
        "task_authority_source",
        "task_authority_sources",
    )


def _metadata_source_types(envelope: ContextEnvelope) -> set[str]:
    return _normalized_metadata_values(envelope.metadata, "source_type", "source_types")


def _is_executable_task_metadata(envelope: ContextEnvelope) -> bool:
    if has_context_flag(envelope, ("creates_executable_task",)):
        return True
    return bool(_action_classes(envelope) & EXECUTABLE_ACTION_CLASSES)


def _action_class(envelope: ContextEnvelope) -> str:
    return normalized_context_key(
        _metadata_value(envelope.metadata, "action_class", "action_classes", "task_kind", "task_kinds")
    )


def _action_classes(envelope: ContextEnvelope) -> set[str]:
    return normalized_context_keys(
        _metadata_values(envelope.metadata, "action_class", "action_classes", "task_kind", "task_kinds")
    )


def _is_stale_generation(envelope: ContextEnvelope) -> bool:
    task_generations = _task_generations(envelope)
    current_generations = _generation_metadata_values(envelope.metadata, *CURRENT_GENERATION_METADATA_KEYS)
    return bool(
        task_generations
        and current_generations
        and any(
            task_generation != current_generation
            for task_generation in task_generations
            for current_generation in current_generations
        )
    )


def _is_wrong_target(envelope: ContextEnvelope) -> bool:
    task_targets = _task_targets(envelope)
    current_targets = _identifier_metadata_values(envelope.metadata, *CURRENT_TARGET_METADATA_KEYS)
    return bool(
        task_targets
        and current_targets
        and any(task_target != current_target for task_target in task_targets for current_target in current_targets)
    )


def _task_target(envelope: ContextEnvelope) -> str:
    return _identifier_value(envelope.target_id) or _first_metadata_identifier(
        envelope.metadata,
        TASK_TARGET_METADATA_KEYS,
    )


def _task_targets(envelope: ContextEnvelope) -> set[str]:
    targets = _identifier_metadata_values(envelope.metadata, *TASK_TARGET_METADATA_KEYS)
    envelope_target = _identifier_value(envelope.target_id)
    if envelope_target:
        targets.add(envelope_target)
    return targets


def _task_generation(envelope: ContextEnvelope) -> str:
    return _generation_value(envelope.active_generation_id) or _first_metadata_value(
        envelope.metadata,
        TASK_GENERATION_METADATA_KEYS,
    )


def _task_generations(envelope: ContextEnvelope) -> set[str]:
    generations = _generation_metadata_values(envelope.metadata, *TASK_GENERATION_METADATA_KEYS)
    envelope_generation = _generation_value(envelope.active_generation_id)
    if envelope_generation:
        generations.add(envelope_generation)
    return generations


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


def _generation_metadata_values(metadata: object, *names: str) -> set[str]:
    values: list[object] = []
    for value in _metadata_values(metadata, *names):
        values.extend(_metadata_scalar_values(value))
    return {generation for value in values if (generation := _generation_value(value))}


def _first_metadata_identifier(metadata: dict[str, object], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = _identifier_value(_metadata_value(metadata, key))
        if value:
            return value
    return ""


def _identifier_value(value: object) -> str:
    return str(value or "").strip().lower()


def _identifier_metadata_values(metadata: object, *names: str) -> set[str]:
    values: list[object] = []
    for value in _metadata_values(metadata, *names):
        values.extend(_metadata_scalar_values(value))
    return {identifier for value in values if (identifier := _identifier_value(value))}


def _supporting_refs(metadata: dict[str, object]) -> list[str]:
    values: list[object] = []
    for refs in _metadata_values(
        metadata,
        "supporting_evidence_ref",
        "supporting_evidence_refs",
        "evidence_ref",
        "evidence_refs",
    ):
        if isinstance(refs, str):
            values.append(refs)
        elif isinstance(refs, (list, tuple, set)):
            values.extend(refs)
    return [_canonical_evidence_ref(item) for item in values if _canonical_evidence_ref(item)]


def _metadata_value(metadata: object, *names: str) -> object | None:
    normalized_names = normalized_context_keys(names)
    if isinstance(metadata, dict):
        items = metadata.items()
    elif isinstance(metadata, (list, tuple, set)):
        for item in metadata:
            nested = _metadata_value(item, *names)
            if nested is not None:
                return nested
        return None
    else:
        return None
    for raw_key, value in items:
        if normalized_context_key(raw_key) in normalized_names:
            return value
        nested = _metadata_value(value, *names)
        if nested is not None:
            return nested
    return None


def _metadata_values(metadata: object, *names: str) -> list[object]:
    normalized_names = normalized_context_keys(names)
    values: list[object] = []
    if isinstance(metadata, dict):
        items = metadata.items()
    elif isinstance(metadata, (list, tuple, set)):
        for item in metadata:
            values.extend(_metadata_values(item, *names))
        return values
    else:
        return values
    for raw_key, value in items:
        if normalized_context_key(raw_key) in normalized_names:
            values.append(value)
        values.extend(_metadata_values(value, *names))
    return values


def _normalized_metadata_values(metadata: object, *names: str) -> set[str]:
    values: list[object] = []
    for value in _metadata_values(metadata, *names):
        values.extend(_metadata_scalar_values(value))
    return normalized_context_keys(values)


def _metadata_scalar_values(value: object) -> list[object]:
    if isinstance(value, (list, tuple, set)):
        values: list[object] = []
        for item in value:
            values.extend(_metadata_scalar_values(item))
        return values
    if isinstance(value, dict):
        return []
    return [value]


def _has_generated_export_path(envelope: ContextEnvelope) -> bool:
    return has_generated_export_path(envelope)


def _cited_supporting_evidence_refs(envelope: ContextEnvelope, refs: list[str]) -> list[str]:
    citation_refs = {_canonical_evidence_ref(item) for item in envelope.citations}
    return [ref for ref in refs if ref in citation_refs]


def _uncited_refs(envelope: ContextEnvelope, refs: list[str]) -> list[str]:
    citation_refs = {_canonical_evidence_ref(item) for item in envelope.citations}
    return [ref for ref in refs if ref not in citation_refs]


def _unresolved_refs(refs: list[str], known_refs: Iterable[str] | None) -> list[str]:
    if known_refs is None:
        return []
    normalized_known_refs = {_canonical_evidence_ref(ref) for ref in known_refs if _canonical_evidence_ref(ref)}
    return [ref for ref in refs if ref not in normalized_known_refs]


def _has_citation_prefix(envelope: ContextEnvelope, prefix: str) -> bool:
    return any(str(item).startswith(prefix) for item in envelope.citations)


def _canonical_evidence_ref(value: object) -> str:
    ref = str(value or "").strip()
    if ref.lower().startswith(EVIDENCE_REF_PREFIX):
        return f"{EVIDENCE_REF_PREFIX}{ref[len(EVIDENCE_REF_PREFIX):].strip()}"
    return ref
