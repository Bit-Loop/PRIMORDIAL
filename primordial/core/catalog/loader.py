from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class CatalogValidationError(ValueError):
    pass


def load_yaml_file(path: Path) -> dict[str, Any]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CatalogValidationError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CatalogValidationError(f"{path} must contain a YAML object")
    return payload


def validate_allowed_fields(payload: dict[str, Any], allowed: set[str], *, source: str) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise CatalogValidationError(f"{source} contains unknown field(s): {', '.join(unknown)}")


def expect_string_list(value: Any, *, source: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CatalogValidationError(f"{source} must be a list of strings")
    return [item for item in value]


def expect_bool(value: Any, *, source: str, default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise CatalogValidationError(f"{source} must be a boolean")
    return value
