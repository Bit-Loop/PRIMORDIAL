from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class ToolInventoryCheck:
    id: str
    mechanism: str


@dataclass(frozen=True, slots=True)
class ToolingGapSubstitution:
    capability: str
    preferred_tool: str
    substitute_tool: str
    rationale: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ScriptSafety:
    generated_helper_scope: str
    forbidden_imports: tuple[str, ...]
    forbidden_calls: tuple[str, ...]
    rejected_behaviors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MethodologyCompilerSpec:
    input_format: str
    output_root: str
    rules: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StructuredAutonomy:
    id: str
    source_path: str
    status: str
    authority: str
    scaffold_support: tuple[str, ...]
    tool_inventory_checks: tuple[ToolInventoryCheck, ...]
    tooling_gap_substitutions: tuple[ToolingGapSubstitution, ...]
    failure_diagnosis_categories: tuple[str, ...]
    script_safety: ScriptSafety
    methodology_compiler: MethodologyCompilerSpec


class StructuredAutonomyCatalog:
    FILENAME = "structured_autonomy.yaml"
    FIELDS = {
        "id",
        "source_path",
        "status",
        "authority",
        "scaffold_support",
        "tool_inventory_checks",
        "tooling_gap_substitutions",
        "failure_diagnosis_categories",
        "script_safety",
        "methodology_compiler",
    }
    TOOL_INVENTORY_FIELDS = {"id", "mechanism"}
    GAP_SUBSTITUTION_FIELDS = {"capability", "preferred_tool", "substitute_tool", "rationale"}
    SCRIPT_SAFETY_FIELDS = {"generated_helper_scope", "forbidden_imports", "forbidden_calls", "rejected_behaviors"}
    METHODOLOGY_COMPILER_FIELDS = {"input_format", "output_root", "rules"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> StructuredAutonomy:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        source_path = _text(payload.get("source_path"), source=f"{path}.source_path")
        if not source_path.endswith(".md"):
            raise CatalogValidationError(f"{path}.source_path must reference a Markdown source")
        return StructuredAutonomy(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_path=source_path,
            status=_text(payload.get("status"), source=f"{path}.status"),
            authority=_text(payload.get("authority"), source=f"{path}.authority"),
            scaffold_support=tuple(expect_string_list(payload.get("scaffold_support"), source=f"{path}.scaffold_support")),
            tool_inventory_checks=tuple(
                self._tool_inventory_check(item, source=f"{path}.tool_inventory_checks[{index}]")
                for index, item in enumerate(
                    _list(payload.get("tool_inventory_checks"), source=f"{path}.tool_inventory_checks")
                )
            ),
            tooling_gap_substitutions=tuple(
                self._tooling_gap_substitution(item, source=f"{path}.tooling_gap_substitutions[{index}]")
                for index, item in enumerate(
                    _list(payload.get("tooling_gap_substitutions"), source=f"{path}.tooling_gap_substitutions")
                )
            ),
            failure_diagnosis_categories=tuple(
                expect_string_list(
                    payload.get("failure_diagnosis_categories"), source=f"{path}.failure_diagnosis_categories"
                )
            ),
            script_safety=self._script_safety(payload.get("script_safety"), source=f"{path}.script_safety"),
            methodology_compiler=self._methodology_compiler(
                payload.get("methodology_compiler"), source=f"{path}.methodology_compiler"
            ),
        )

    def _tool_inventory_check(self, payload: Any, *, source: str) -> ToolInventoryCheck:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.TOOL_INVENTORY_FIELDS, source=source)
        return ToolInventoryCheck(
            id=_text(data.get("id"), source=f"{source}.id"),
            mechanism=_text(data.get("mechanism"), source=f"{source}.mechanism"),
        )

    def _tooling_gap_substitution(self, payload: Any, *, source: str) -> ToolingGapSubstitution:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.GAP_SUBSTITUTION_FIELDS, source=source)
        return ToolingGapSubstitution(
            capability=_text(data.get("capability"), source=f"{source}.capability"),
            preferred_tool=_text(data.get("preferred_tool"), source=f"{source}.preferred_tool"),
            substitute_tool=_text(data.get("substitute_tool"), source=f"{source}.substitute_tool"),
            rationale=tuple(expect_string_list(data.get("rationale"), source=f"{source}.rationale")),
        )

    def _script_safety(self, payload: Any, *, source: str) -> ScriptSafety:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.SCRIPT_SAFETY_FIELDS, source=source)
        return ScriptSafety(
            generated_helper_scope=_text(data.get("generated_helper_scope"), source=f"{source}.generated_helper_scope"),
            forbidden_imports=tuple(expect_string_list(data.get("forbidden_imports"), source=f"{source}.forbidden_imports")),
            forbidden_calls=tuple(expect_string_list(data.get("forbidden_calls"), source=f"{source}.forbidden_calls")),
            rejected_behaviors=tuple(
                expect_string_list(data.get("rejected_behaviors"), source=f"{source}.rejected_behaviors")
            ),
        )

    def _methodology_compiler(self, payload: Any, *, source: str) -> MethodologyCompilerSpec:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.METHODOLOGY_COMPILER_FIELDS, source=source)
        return MethodologyCompilerSpec(
            input_format=_text(data.get("input_format"), source=f"{source}.input_format"),
            output_root=_text(data.get("output_root"), source=f"{source}.output_root"),
            rules=tuple(expect_string_list(data.get("rules"), source=f"{source}.rules")),
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
