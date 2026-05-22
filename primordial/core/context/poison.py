from __future__ import annotations

from typing import Iterable

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_context_key, normalized_context_keys


TRUTHY_METADATA_FLAG_VALUES = frozenset({"1", "on", "true", "yes"})


def has_context_flag(envelope: ContextEnvelope, names: Iterable[str]) -> bool:
    flag_names = normalized_context_keys(names)
    poison_flags = normalized_context_keys(envelope.poison_flags)
    metadata_flags = {
        key
        for raw_key, value in envelope.metadata.items()
        if _is_metadata_flag_enabled(value) and (key := normalized_context_key(raw_key))
    }
    return bool(flag_names & (poison_flags | metadata_flags))


def _is_metadata_flag_enabled(value: object) -> bool:
    return value is True or normalized_context_key(value) in TRUTHY_METADATA_FLAG_VALUES
