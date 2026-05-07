from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError

_TOKEN = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\}\}")


def interpolate(value: str, context: Mapping[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        resolved: Any = context
        for part in key.split("."):
            if isinstance(resolved, Mapping) and part in resolved:
                resolved = resolved[part]
            else:
                raise CatalogValidationError(f"unknown interpolation variable: {key}")
        if isinstance(resolved, str | int | float):
            return str(resolved)
        raise CatalogValidationError(f"interpolation variable {key} is not scalar")

    return _TOKEN.sub(replace, value)


def interpolate_argv(argv: list[str], context: Mapping[str, Any]) -> list[str]:
    return [interpolate(item, context) for item in argv]
