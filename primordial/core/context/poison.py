from __future__ import annotations

from typing import Iterable

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys


TRUTHY_METADATA_FLAG_VALUES = frozenset({"1", "on", "true", "yes"})
POISON_FLAGS_METADATA_KEYS = frozenset({"poison_flag", "poison_flags"})


def has_context_flag(envelope: ContextEnvelope, names: Iterable[str]) -> bool:
    flag_names = normalized_context_keys(names)
    poison_flags = normalized_context_keys(envelope.poison_flags)
    metadata_flags = _metadata_flags(envelope.metadata)
    return bool(flag_names & (poison_flags | metadata_flags))


def _metadata_flags(value: object) -> set[str]:
    flags: set[str] = set()
    if isinstance(value, dict):
        for raw_key, item in value.items():
            key = normalized_context_key(raw_key)
            if key in POISON_FLAGS_METADATA_KEYS:
                flags.update(_metadata_flag_values(item))
            if _is_metadata_flag_enabled(item) and key:
                flags.add(key)
            flags.update(_metadata_flags(item))
        return flags
    if isinstance(value, (frozenset, list, set, tuple)):
        for item in value:
            flags.update(_metadata_flags(item))
    return flags


def _is_metadata_flag_enabled(value: object) -> bool:
    if isinstance(value, (frozenset, list, set, tuple)):
        return any(_is_metadata_flag_enabled(item) for item in value)
    return value is True or normalized_context_key(value) in TRUTHY_METADATA_FLAG_VALUES


def _metadata_flag_values(value: object) -> set[str]:
    if isinstance(value, dict):
        return set()
    if isinstance(value, (frozenset, list, set, tuple)):
        values: set[str] = set()
        for item in value:
            values.update(_metadata_flag_values(item))
        return values
    key = normalized_context_key(value)
    return {key} if key else set()
