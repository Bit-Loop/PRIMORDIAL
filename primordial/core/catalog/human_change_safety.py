from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class HumanChangeAuthorityLayer:
    id: str
    path: str


@dataclass(frozen=True, slots=True)
class HumanChangeSafety:
    id: str
    source_path: str
    status: str
    authority: str
    read_first: tuple[str, ...]
    execution_order: tuple[str, ...]
    core_rules: tuple[str, ...]
    source_runtime_boundaries: tuple[str, ...]
    change_types: tuple[str, ...]
    authority_layers: tuple[HumanChangeAuthorityLayer, ...]
    change_workflow: tuple[str, ...]
    validation_commands: tuple[str, ...]
    operator_surface_checks: tuple[str, ...]
    avoid: tuple[str, ...]


class HumanChangeSafetyCatalog:
    FILENAME = "human_change_safety.yaml"
    FIELDS = {
        "id",
        "source_path",
        "status",
        "authority",
        "read_first",
        "execution_order",
        "core_rules",
        "source_runtime_boundaries",
        "change_types",
        "authority_layers",
        "change_workflow",
        "validation_commands",
        "operator_surface_checks",
        "avoid",
    }
    AUTHORITY_LAYER_FIELDS = {"id", "path"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> HumanChangeSafety:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        source_path = _text(payload.get("source_path"), source=f"{path}.source_path")
        if not source_path.endswith(".md"):
            raise CatalogValidationError(f"{path}.source_path must reference a Markdown source")
        return HumanChangeSafety(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_path=source_path,
            status=_text(payload.get("status"), source=f"{path}.status"),
            authority=_text(payload.get("authority"), source=f"{path}.authority"),
            read_first=tuple(expect_string_list(payload.get("read_first"), source=f"{path}.read_first")),
            execution_order=tuple(expect_string_list(payload.get("execution_order"), source=f"{path}.execution_order")),
            core_rules=tuple(expect_string_list(payload.get("core_rules"), source=f"{path}.core_rules")),
            source_runtime_boundaries=tuple(
                expect_string_list(payload.get("source_runtime_boundaries"), source=f"{path}.source_runtime_boundaries")
            ),
            change_types=tuple(expect_string_list(payload.get("change_types"), source=f"{path}.change_types")),
            authority_layers=tuple(
                self._authority_layer(item, source=f"{path}.authority_layers[{index}]")
                for index, item in enumerate(_list(payload.get("authority_layers"), source=f"{path}.authority_layers"))
            ),
            change_workflow=tuple(expect_string_list(payload.get("change_workflow"), source=f"{path}.change_workflow")),
            validation_commands=tuple(
                expect_string_list(payload.get("validation_commands"), source=f"{path}.validation_commands")
            ),
            operator_surface_checks=tuple(
                expect_string_list(payload.get("operator_surface_checks"), source=f"{path}.operator_surface_checks")
            ),
            avoid=tuple(expect_string_list(payload.get("avoid"), source=f"{path}.avoid")),
        )

    def _authority_layer(self, payload: Any, *, source: str) -> HumanChangeAuthorityLayer:
        if not isinstance(payload, dict):
            raise CatalogValidationError(f"{source} must be an object")
        validate_allowed_fields(payload, self.AUTHORITY_LAYER_FIELDS, source=source)
        return HumanChangeAuthorityLayer(
            id=_text(payload.get("id"), source=f"{source}.id"),
            path=_text(payload.get("path"), source=f"{source}.path"),
        )


def _list(value: Any, *, source: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise CatalogValidationError(f"{source} must be a list")
    return value


def _text(value: Any, *, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogValidationError(f"{source} must be a non-empty string")
    return value.strip()
