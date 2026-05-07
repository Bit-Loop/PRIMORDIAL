from __future__ import annotations

from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, load_yaml_file


class HeuristicCatalog:
    def __init__(self, root: Path) -> None:
        self.root = root

    def load(self, name: str) -> dict[str, Any]:
        path = self.root / f"{name}.yaml"
        return load_yaml_file(path)

    def string_tuple(self, name: str, key: str) -> tuple[str, ...]:
        value = self.load(name).get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise CatalogValidationError(f"{name}.{key} must be a list of strings")
        return tuple(value)

    def int_tuple(self, name: str, key: str) -> tuple[int, ...]:
        value = self.load(name).get(key, [])
        if not isinstance(value, list):
            raise CatalogValidationError(f"{name}.{key} must be a list")
        return tuple(int(item) for item in value)

    def int_map(self, name: str, key: str) -> dict[int, str]:
        value = self.load(name).get(key, {})
        if not isinstance(value, dict):
            raise CatalogValidationError(f"{name}.{key} must be an object")
        return {int(port): str(service) for port, service in value.items()}
