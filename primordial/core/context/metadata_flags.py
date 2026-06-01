from __future__ import annotations

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys


FALSY_METADATA_FLAG_VALUES = frozenset({"0", "false", "no", "off"})


def metadata_value_is_false(envelope: ContextEnvelope, name: str) -> bool:
    for value in _metadata_values_from(envelope.metadata, name):
        for scalar in _metadata_scalar_values(value):
            if scalar is False or normalized_context_key(scalar) in FALSY_METADATA_FLAG_VALUES:
                return True
    return False


def raw_metadata_value(envelope: ContextEnvelope, *names: str) -> object | None:
    normalized_names = normalized_context_keys(names)
    return _raw_metadata_value(envelope.metadata, normalized_names)


def _raw_metadata_value(value: object, normalized_names: set[str]) -> object | None:
    if isinstance(value, dict):
        for raw_key, item in value.items():
            if normalized_context_key(raw_key) in normalized_names:
                return item
        for item in value.values():
            nested = _raw_metadata_value(item, normalized_names)
            if nested is not None:
                return nested
    if isinstance(value, (frozenset, list, set, tuple)):
        for item in value:
            nested = _raw_metadata_value(item, normalized_names)
            if nested is not None:
                return nested
    return None


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
