from __future__ import annotations

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys


OPERATOR_NOTE_SOURCE_TYPES = frozenset({"manual_artifact", "notion"})
RAW_CHAT_SOURCE_TYPES = frozenset({"chat"})


def operator_note_source_omission_reason(envelope: ContextEnvelope) -> str:
    if envelope.source_type in RAW_CHAT_SOURCE_TYPES:
        return ""
    if envelope.kind != "operator_note":
        return ""
    source_types = {normalized_context_key(envelope.source_type), *_metadata_text_values(envelope, "source_type")}
    if source_types - OPERATOR_NOTE_SOURCE_TYPES:
        return "non_operator_note_source"
    return ""


def _metadata_text_values(envelope: ContextEnvelope, *names: str) -> set[str]:
    values: set[str] = set()
    for value in _metadata_values_from(envelope.metadata, *names):
        text = normalized_context_key(value)
        if text:
            values.add(text)
    return values


def _metadata_values_from(value: object, *names: str) -> list[object]:
    normalized_names = normalized_context_keys(names)
    if "source_type" in normalized_names:
        normalized_names.add("source_types")
    values: list[object] = []
    if isinstance(value, dict):
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) in normalized_names:
                values.append(item)
            values.extend(_metadata_values_from(item, *names))
    elif isinstance(value, (frozenset, list, set, tuple)):
        for item in value:
            values.extend(_metadata_values_from(item, *names))
    return values
