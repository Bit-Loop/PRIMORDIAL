from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class RequirementGroup:
    id: str
    requirements: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ArchitectureComponent:
    id: str
    capabilities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AIAgentPrd:
    id: str
    source_path: str
    status: str
    last_updated: str
    overview: tuple[str, ...]
    problem_statement: tuple[str, ...]
    vision: tuple[str, ...]
    target_users: tuple[str, ...]
    primary_use_cases: tuple[str, ...]
    non_goals: tuple[str, ...]
    core_requirements: tuple[RequirementGroup, ...]
    functional_components: tuple[RequirementGroup, ...]
    operating_model: tuple[str, ...]
    required_architecture_components: tuple[ArchitectureComponent, ...]
    architecture_shifts: tuple[str, ...]


class AIAgentPrdCatalog:
    FILENAME = "ai_agent_prd.yaml"
    FIELDS = {
        "id",
        "source_path",
        "status",
        "last_updated",
        "overview",
        "problem_statement",
        "vision",
        "target_users",
        "primary_use_cases",
        "non_goals",
        "core_requirements",
        "functional_components",
        "operating_model",
        "required_architecture_components",
        "architecture_shifts",
    }
    REQUIREMENT_FIELDS = {"id", "requirements"}
    COMPONENT_FIELDS = {"id", "capabilities"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> AIAgentPrd:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        return AIAgentPrd(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_path=_text(payload.get("source_path"), source=f"{path}.source_path"),
            status=_text(payload.get("status"), source=f"{path}.status"),
            last_updated=_text(payload.get("last_updated"), source=f"{path}.last_updated"),
            overview=tuple(expect_string_list(payload.get("overview"), source=f"{path}.overview")),
            problem_statement=tuple(expect_string_list(payload.get("problem_statement"), source=f"{path}.problem_statement")),
            vision=tuple(expect_string_list(payload.get("vision"), source=f"{path}.vision")),
            target_users=tuple(expect_string_list(payload.get("target_users"), source=f"{path}.target_users")),
            primary_use_cases=tuple(expect_string_list(payload.get("primary_use_cases"), source=f"{path}.primary_use_cases")),
            non_goals=tuple(expect_string_list(payload.get("non_goals"), source=f"{path}.non_goals")),
            core_requirements=tuple(
                self._requirement_group(item, source=f"{path}.core_requirements[{index}]")
                for index, item in enumerate(_list(payload.get("core_requirements"), source=f"{path}.core_requirements"))
            ),
            functional_components=tuple(
                self._requirement_group(item, source=f"{path}.functional_components[{index}]")
                for index, item in enumerate(
                    _list(payload.get("functional_components"), source=f"{path}.functional_components")
                )
            ),
            operating_model=tuple(expect_string_list(payload.get("operating_model"), source=f"{path}.operating_model")),
            required_architecture_components=tuple(
                self._architecture_component(item, source=f"{path}.required_architecture_components[{index}]")
                for index, item in enumerate(
                    _list(
                        payload.get("required_architecture_components"),
                        source=f"{path}.required_architecture_components",
                    )
                )
            ),
            architecture_shifts=tuple(
                expect_string_list(payload.get("architecture_shifts"), source=f"{path}.architecture_shifts")
            ),
        )

    def _requirement_group(self, payload: Any, *, source: str) -> RequirementGroup:
        if not isinstance(payload, dict):
            raise CatalogValidationError(f"{source} must be an object")
        validate_allowed_fields(payload, self.REQUIREMENT_FIELDS, source=source)
        return RequirementGroup(
            id=_text(payload.get("id"), source=f"{source}.id"),
            requirements=tuple(expect_string_list(payload.get("requirements"), source=f"{source}.requirements")),
        )

    def _architecture_component(self, payload: Any, *, source: str) -> ArchitectureComponent:
        if not isinstance(payload, dict):
            raise CatalogValidationError(f"{source} must be an object")
        validate_allowed_fields(payload, self.COMPONENT_FIELDS, source=source)
        return ArchitectureComponent(
            id=_text(payload.get("id"), source=f"{source}.id"),
            capabilities=tuple(expect_string_list(payload.get("capabilities"), source=f"{source}.capabilities")),
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
