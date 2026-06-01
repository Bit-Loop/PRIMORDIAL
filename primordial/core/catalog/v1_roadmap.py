from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class V1Phase:
    id: str
    title: str
    goals: tuple[str, ...]
    acceptance_criteria: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class V1Roadmap:
    id: str
    source_path: str
    status: str
    last_updated: str
    archived_sections: tuple[str, ...]
    locked_decisions: tuple[str, ...]
    model_storage: dict[str, Any]
    target_model_set: tuple[str, ...]
    explicit_deferrals: tuple[str, ...]
    immediate_execution_order: tuple[str, ...]
    phases: tuple[V1Phase, ...]


class V1RoadmapCatalog:
    FILENAME = "v1_roadmap.yaml"
    FIELDS = {
        "id",
        "source_path",
        "status",
        "last_updated",
        "archived_sections",
        "locked_decisions",
        "model_storage",
        "target_model_set",
        "explicit_deferrals",
        "immediate_execution_order",
        "phases",
    }
    PHASE_FIELDS = {"id", "title", "goals", "acceptance_criteria"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> V1Roadmap:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        phases = tuple(
            self._phase(item, source=f"{path}.phases[{index}]")
            for index, item in enumerate(_list(payload.get("phases"), source=f"{path}.phases"))
        )
        return V1Roadmap(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_path=_text(payload.get("source_path"), source=f"{path}.source_path"),
            status=_text(payload.get("status"), source=f"{path}.status"),
            last_updated=_text(payload.get("last_updated"), source=f"{path}.last_updated"),
            archived_sections=tuple(expect_string_list(payload.get("archived_sections"), source=f"{path}.archived_sections")),
            locked_decisions=tuple(expect_string_list(payload.get("locked_decisions"), source=f"{path}.locked_decisions")),
            model_storage=_object(payload.get("model_storage"), source=f"{path}.model_storage"),
            target_model_set=tuple(expect_string_list(payload.get("target_model_set"), source=f"{path}.target_model_set")),
            explicit_deferrals=tuple(
                expect_string_list(payload.get("explicit_deferrals"), source=f"{path}.explicit_deferrals")
            ),
            immediate_execution_order=tuple(
                expect_string_list(payload.get("immediate_execution_order"), source=f"{path}.immediate_execution_order")
            ),
            phases=phases,
        )

    def _phase(self, payload: Any, *, source: str) -> V1Phase:
        if not isinstance(payload, dict):
            raise CatalogValidationError(f"{source} must be an object")
        validate_allowed_fields(payload, self.PHASE_FIELDS, source=source)
        return V1Phase(
            id=_text(payload.get("id"), source=f"{source}.id"),
            title=_text(payload.get("title"), source=f"{source}.title"),
            goals=tuple(expect_string_list(payload.get("goals"), source=f"{source}.goals")),
            acceptance_criteria=tuple(
                expect_string_list(payload.get("acceptance_criteria"), source=f"{source}.acceptance_criteria")
            ),
        )


def _text(value: Any, *, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogValidationError(f"{source} must be a non-empty string")
    return value.strip()


def _list(value: Any, *, source: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise CatalogValidationError(f"{source} must be a list")
    return value


def _object(value: Any, *, source: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise CatalogValidationError(f"{source} must be an object")
    return value
