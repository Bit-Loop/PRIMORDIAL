from __future__ import annotations

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys


FALSY_METADATA_FLAG_VALUES = frozenset({"0", "false", "no", "off"})


def metadata_value_is_false(envelope: ContextEnvelope, name: str) -> bool:
    value = raw_metadata_value(envelope, name)
    return value is False or normalized_context_key(value) in FALSY_METADATA_FLAG_VALUES


def raw_metadata_value(envelope: ContextEnvelope, *names: str) -> object | None:
    normalized_names = normalized_context_keys(names)
    for raw_key, value in envelope.metadata.items():
        if normalized_context_key(raw_key) in normalized_names:
            return value
    return None
