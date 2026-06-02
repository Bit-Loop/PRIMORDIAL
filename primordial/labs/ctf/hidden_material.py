from __future__ import annotations

import re
from typing import Any, Mapping


HIDDEN_FLAG_KEYS = frozenset(
    {
        "expected_flag",
        "expected_flags",
        "flag",
        "flags",
        "raw_flag",
        "raw_flags",
        "hidden_flag",
        "hidden_flags",
    }
)
FLAG_PATTERN = re.compile(r"\b(?:(?i:flag|ctf)|(?:[A-Z][A-Z0-9_-]{1,31}-\d+))\{[^}\s]{4,}\}")


def reject_hidden_flag_material(value: Any, *, path: str, label: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key).strip()
            if normalized_hidden_material_key(key_text) in HIDDEN_FLAG_KEYS:
                raise ValueError(f"{label} must not expose raw flag/hidden flag material at {path}.{key_text}")
            reject_hidden_flag_material(child, path=f"{path}.{key_text}", label=label)
    elif isinstance(value, list | tuple):
        for index, child in enumerate(value):
            reject_hidden_flag_material(child, path=f"{path}[{index}]", label=label)
    elif FLAG_PATTERN.search(str(value)):
        raise ValueError(f"{label} must not expose raw flag/hidden flag material at {path}")


def normalized_hidden_material_key(value: str) -> str:
    return "_".join(str(value).strip().lower().replace("-", " ").split())
