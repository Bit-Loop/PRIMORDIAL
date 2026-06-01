from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class LayoutArea:
    path: str
    role: str
    guidance: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EditPath:
    id: str
    title: str
    files: tuple[str, ...]
    ordered_steps: tuple[str, ...]
    rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UIEditArea:
    id: str
    files: tuple[str, ...]
    areas: tuple[str, ...]
    known_issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TestMapEntry:
    path: str
    coverage: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CodebaseFloorPlan:
    id: str
    source_path: str
    status: str
    authority: str
    purpose: tuple[str, ...]
    top_level_layout: tuple[LayoutArea, ...]
    common_edit_paths: tuple[EditPath, ...]
    current_ui_edit_areas: tuple[UIEditArea, ...]
    test_map: tuple[TestMapEntry, ...]
    refactor_priorities: tuple[str, ...]


class CodebaseFloorPlanCatalog:
    FILENAME = "codebase_floor_plan.yaml"
    FIELDS = {
        "id",
        "source_path",
        "status",
        "authority",
        "purpose",
        "top_level_layout",
        "common_edit_paths",
        "current_ui_edit_areas",
        "test_map",
        "refactor_priorities",
    }
    LAYOUT_FIELDS = {"path", "role", "guidance"}
    EDIT_PATH_FIELDS = {"id", "title", "files", "ordered_steps", "rules"}
    UI_AREA_FIELDS = {"id", "files", "areas", "known_issues"}
    TEST_MAP_FIELDS = {"path", "coverage"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> CodebaseFloorPlan:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        source_path = _text(payload.get("source_path"), source=f"{path}.source_path")
        if not source_path.endswith(".md"):
            raise CatalogValidationError(f"{path}.source_path must reference a Markdown source")
        return CodebaseFloorPlan(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_path=source_path,
            status=_text(payload.get("status"), source=f"{path}.status"),
            authority=_text(payload.get("authority"), source=f"{path}.authority"),
            purpose=tuple(expect_string_list(payload.get("purpose"), source=f"{path}.purpose")),
            top_level_layout=tuple(
                self._layout_area(item, source=f"{path}.top_level_layout[{index}]")
                for index, item in enumerate(_list(payload.get("top_level_layout"), source=f"{path}.top_level_layout"))
            ),
            common_edit_paths=tuple(
                self._edit_path(item, source=f"{path}.common_edit_paths[{index}]")
                for index, item in enumerate(_list(payload.get("common_edit_paths"), source=f"{path}.common_edit_paths"))
            ),
            current_ui_edit_areas=tuple(
                self._ui_area(item, source=f"{path}.current_ui_edit_areas[{index}]")
                for index, item in enumerate(
                    _list(payload.get("current_ui_edit_areas"), source=f"{path}.current_ui_edit_areas")
                )
            ),
            test_map=tuple(
                self._test_map_entry(item, source=f"{path}.test_map[{index}]")
                for index, item in enumerate(_list(payload.get("test_map"), source=f"{path}.test_map"))
            ),
            refactor_priorities=tuple(
                expect_string_list(payload.get("refactor_priorities"), source=f"{path}.refactor_priorities")
            ),
        )

    def _layout_area(self, payload: Any, *, source: str) -> LayoutArea:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.LAYOUT_FIELDS, source=source)
        return LayoutArea(
            path=_text(data.get("path"), source=f"{source}.path"),
            role=_text(data.get("role"), source=f"{source}.role"),
            guidance=tuple(expect_string_list(data.get("guidance"), source=f"{source}.guidance")),
        )

    def _edit_path(self, payload: Any, *, source: str) -> EditPath:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.EDIT_PATH_FIELDS, source=source)
        return EditPath(
            id=_text(data.get("id"), source=f"{source}.id"),
            title=_text(data.get("title"), source=f"{source}.title"),
            files=tuple(expect_string_list(data.get("files"), source=f"{source}.files")),
            ordered_steps=tuple(expect_string_list(data.get("ordered_steps"), source=f"{source}.ordered_steps")),
            rules=tuple(expect_string_list(data.get("rules"), source=f"{source}.rules")),
        )

    def _ui_area(self, payload: Any, *, source: str) -> UIEditArea:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.UI_AREA_FIELDS, source=source)
        return UIEditArea(
            id=_text(data.get("id"), source=f"{source}.id"),
            files=tuple(expect_string_list(data.get("files"), source=f"{source}.files")),
            areas=tuple(expect_string_list(data.get("areas"), source=f"{source}.areas")),
            known_issues=tuple(expect_string_list(data.get("known_issues"), source=f"{source}.known_issues")),
        )

    def _test_map_entry(self, payload: Any, *, source: str) -> TestMapEntry:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.TEST_MAP_FIELDS, source=source)
        return TestMapEntry(
            path=_text(data.get("path"), source=f"{source}.path"),
            coverage=tuple(expect_string_list(data.get("coverage"), source=f"{source}.coverage")),
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
