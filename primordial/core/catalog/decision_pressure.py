from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class ConflictSide:
    label: str
    snippet: str
    pros: tuple[str, ...]
    cons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DecisionConflict:
    id: str
    title: str
    source_of_difference: str
    side_a: ConflictSide
    side_b: ConflictSide
    grand_scheme_importance: str
    default_resolution: str
    resolution_idea: str
    resolution_guards: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DecisionPressureMap:
    id: str
    source_path: str
    status: str
    authority: str
    reading_frame: tuple[str, ...]
    conflicts: tuple[DecisionConflict, ...]
    cross_cutting_principles: tuple[str, ...]


class DecisionPressureCatalog:
    FILENAME = "decision_pressure.yaml"
    FIELDS = {
        "id",
        "source_path",
        "status",
        "authority",
        "reading_frame",
        "conflicts",
        "cross_cutting_principles",
    }
    CONFLICT_FIELDS = {
        "id",
        "title",
        "source_of_difference",
        "side_a",
        "side_b",
        "grand_scheme_importance",
        "default_resolution",
        "resolution_idea",
        "resolution_guards",
    }
    SIDE_FIELDS = {"label", "snippet", "pros", "cons"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> DecisionPressureMap:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        source_path = _text(payload.get("source_path"), source=f"{path}.source_path")
        if not source_path.endswith(".md"):
            raise CatalogValidationError(f"{path}.source_path must reference a Markdown source")
        return DecisionPressureMap(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_path=source_path,
            status=_text(payload.get("status"), source=f"{path}.status"),
            authority=_text(payload.get("authority"), source=f"{path}.authority"),
            reading_frame=tuple(expect_string_list(payload.get("reading_frame"), source=f"{path}.reading_frame")),
            conflicts=tuple(
                self._conflict(item, source=f"{path}.conflicts[{index}]")
                for index, item in enumerate(_list(payload.get("conflicts"), source=f"{path}.conflicts"))
            ),
            cross_cutting_principles=tuple(
                expect_string_list(payload.get("cross_cutting_principles"), source=f"{path}.cross_cutting_principles")
            ),
        )

    def _conflict(self, payload: Any, *, source: str) -> DecisionConflict:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.CONFLICT_FIELDS, source=source)
        return DecisionConflict(
            id=_text(data.get("id"), source=f"{source}.id"),
            title=_text(data.get("title"), source=f"{source}.title"),
            source_of_difference=_text(data.get("source_of_difference"), source=f"{source}.source_of_difference"),
            side_a=self._side(data.get("side_a"), source=f"{source}.side_a"),
            side_b=self._side(data.get("side_b"), source=f"{source}.side_b"),
            grand_scheme_importance=_text(
                data.get("grand_scheme_importance"), source=f"{source}.grand_scheme_importance"
            ),
            default_resolution=_text(data.get("default_resolution"), source=f"{source}.default_resolution"),
            resolution_idea=_text(data.get("resolution_idea"), source=f"{source}.resolution_idea"),
            resolution_guards=tuple(
                expect_string_list(data.get("resolution_guards"), source=f"{source}.resolution_guards")
            ),
        )

    def _side(self, payload: Any, *, source: str) -> ConflictSide:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.SIDE_FIELDS, source=source)
        return ConflictSide(
            label=_text(data.get("label"), source=f"{source}.label"),
            snippet=_text(data.get("snippet"), source=f"{source}.snippet"),
            pros=tuple(expect_string_list(data.get("pros"), source=f"{source}.pros")),
            cons=tuple(expect_string_list(data.get("cons"), source=f"{source}.cons")),
        )


def _object(value: Any, *, source: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogValidationError(f"{source} must be an object")
    return value


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
