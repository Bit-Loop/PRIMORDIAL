from __future__ import annotations

import re
from typing import Iterable, Mapping


def normalized_context_key(value: object) -> str:
    text = "" if value is None else str(value)
    return re.sub(r"[^a-z0-9]+", "_", text.strip().lower()).strip("_")


def normalized_context_keys(values: Iterable[object]) -> set[str]:
    return {key for value in values if (key := normalized_context_key(value))}


def normalized_metadata_value(metadata: Mapping[str, object], *names: object) -> str:
    normalized_names = normalized_context_keys(names)
    for raw_key, value in metadata.items():
        if normalized_context_key(raw_key) in normalized_names:
            return normalized_context_key(value)
    return ""
