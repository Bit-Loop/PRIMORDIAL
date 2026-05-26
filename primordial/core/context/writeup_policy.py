from __future__ import annotations

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.metadata_flags import metadata_value_is_false
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys


POSTMORTEM_MODES = frozenset({"postmortem", "postmortem_only", "postmortem-only"})
POSTMORTEM_ONLY_WRITEUP_POLICIES = frozenset({"postmortem_only", "postmortem-only"})
FORBIDDEN_WRITEUP_POLICIES = frozenset(
    {
        "closed_book",
        "closed-book",
        "forbid",
        "forbidden",
        "deny",
        "denied",
        "exclude",
        "excluded",
        "closed_book_excluded",
    }
)
CLOSED_BOOK_MODES = frozenset({"closed_book", "closed-book", "closed_book_mode"})
WRITEUP_SOURCE_TYPES = frozenset({"writeup"})


def prompt_writeup_omission_reason(envelope: ContextEnvelope, *, role: str) -> str:
    if role not in {"ctf_solver_orchestrator", "methodology_advisor", "report_writer"}:
        return ""
    if _is_closed_book_writeup(envelope):
        return "closed_book_forbidden"
    if _has_forbidden_writeup_policy(envelope):
        return "writeups_forbidden"
    if _has_disabled_writeups(envelope):
        return "writeups_forbidden"
    if _is_postmortem_only_writeup_outside_postmortem_scope(envelope):
        return "postmortem_only_forbidden"
    return ""


def _is_closed_book_writeup(envelope: ContextEnvelope) -> bool:
    return _has_writeup_source_type(envelope) and _closed_book_mode(envelope)


def _closed_book_mode(envelope: ContextEnvelope) -> bool:
    modes = _metadata_text_values(envelope.metadata, "benchmark_mode", "mode")
    return bool(modes & CLOSED_BOOK_MODES)


def _has_disabled_writeups(envelope: ContextEnvelope) -> bool:
    return _has_writeup_source_type(envelope) and metadata_value_is_false(envelope, "writeups_allowed")


def _has_forbidden_writeup_policy(envelope: ContextEnvelope) -> bool:
    policies = _metadata_text_values(envelope.metadata, "writeup_access_policy")
    return _has_writeup_source_type(envelope) and bool(policies & FORBIDDEN_WRITEUP_POLICIES)


def _is_postmortem_only_writeup_outside_postmortem_scope(envelope: ContextEnvelope) -> bool:
    policies = _metadata_text_values(envelope.metadata, "writeup_access_policy")
    return (
        _has_writeup_source_type(envelope)
        and bool(policies & POSTMORTEM_ONLY_WRITEUP_POLICIES)
        and not _is_postmortem_scoped(envelope)
    )


def _is_postmortem_scoped(envelope: ContextEnvelope) -> bool:
    scoped_values = _metadata_text_values(envelope.metadata, "benchmark_mode", "mode", "purpose")
    scoped_values.add(normalized_context_key(envelope.purpose))
    return bool(scoped_values & POSTMORTEM_MODES)


def _has_writeup_source_type(envelope: ContextEnvelope) -> bool:
    return bool(_source_types(envelope) & WRITEUP_SOURCE_TYPES)


def _source_types(envelope: ContextEnvelope) -> set[str]:
    return {normalized_context_key(envelope.source_type), *_metadata_text_values(envelope.metadata, "source_type", "source_types")}


def _metadata_text_values(value: object, *names: str) -> set[str]:
    values: set[str] = set()
    for item in _metadata_values_from(value, *names):
        for scalar in _metadata_scalar_values(item):
            text = normalized_context_key(scalar)
            if text:
                values.add(text)
    return values


def _metadata_values_from(value: object, *names: str) -> list[object]:
    normalized_names = normalized_context_keys(names)
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
