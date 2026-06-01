from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class AssistantLayerRef:
    id: str
    path: str


@dataclass(frozen=True, slots=True)
class AssistantOperatingContract:
    id: str
    source_paths: tuple[str, ...]
    status: str
    authority: str
    project_model: tuple[str, ...]
    invariants: tuple[str, ...]
    operational_priority_order: tuple[str, ...]
    layer_order: tuple[str, ...]
    layer_map: tuple[AssistantLayerRef, ...]
    execution_model: tuple[str, ...]
    validation_commands: tuple[str, ...]
    cli_commands: tuple[str, ...]
    required_trace_metadata: tuple[str, ...]
    tooling_inventory_rules: tuple[str, ...]
    resource_budget_rules: tuple[str, ...]
    failure_containment_rules: tuple[str, ...]
    concurrency_rules: tuple[str, ...]
    evidence_progression_rules: tuple[str, ...]
    model_routing_rules: tuple[str, ...]
    methodology_rules: tuple[str, ...]
    markdown_governance: tuple[str, ...]


class AssistantOperatingContractCatalog:
    FILENAME = "assistant_operating_contract.yaml"
    FIELDS = {
        "id",
        "source_paths",
        "status",
        "authority",
        "project_model",
        "invariants",
        "operational_priority_order",
        "layer_order",
        "layer_map",
        "execution_model",
        "validation_commands",
        "cli_commands",
        "required_trace_metadata",
        "tooling_inventory_rules",
        "resource_budget_rules",
        "failure_containment_rules",
        "concurrency_rules",
        "evidence_progression_rules",
        "model_routing_rules",
        "methodology_rules",
        "markdown_governance",
    }
    LAYER_FIELDS = {"id", "path"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> AssistantOperatingContract:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        source_paths = tuple(expect_string_list(payload.get("source_paths"), source=f"{path}.source_paths"))
        for source_path in source_paths:
            if not source_path.endswith(".md"):
                raise CatalogValidationError(f"{path}.source_paths must reference Markdown sources")
        return AssistantOperatingContract(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_paths=source_paths,
            status=_text(payload.get("status"), source=f"{path}.status"),
            authority=_text(payload.get("authority"), source=f"{path}.authority"),
            project_model=tuple(expect_string_list(payload.get("project_model"), source=f"{path}.project_model")),
            invariants=tuple(expect_string_list(payload.get("invariants"), source=f"{path}.invariants")),
            operational_priority_order=tuple(
                expect_string_list(payload.get("operational_priority_order"), source=f"{path}.operational_priority_order")
            ),
            layer_order=tuple(expect_string_list(payload.get("layer_order"), source=f"{path}.layer_order")),
            layer_map=tuple(
                self._layer_ref(item, source=f"{path}.layer_map[{index}]")
                for index, item in enumerate(_list(payload.get("layer_map"), source=f"{path}.layer_map"))
            ),
            execution_model=tuple(expect_string_list(payload.get("execution_model"), source=f"{path}.execution_model")),
            validation_commands=tuple(
                expect_string_list(payload.get("validation_commands"), source=f"{path}.validation_commands")
            ),
            cli_commands=tuple(expect_string_list(payload.get("cli_commands"), source=f"{path}.cli_commands")),
            required_trace_metadata=tuple(
                expect_string_list(payload.get("required_trace_metadata"), source=f"{path}.required_trace_metadata")
            ),
            tooling_inventory_rules=tuple(
                expect_string_list(payload.get("tooling_inventory_rules"), source=f"{path}.tooling_inventory_rules")
            ),
            resource_budget_rules=tuple(
                expect_string_list(payload.get("resource_budget_rules"), source=f"{path}.resource_budget_rules")
            ),
            failure_containment_rules=tuple(
                expect_string_list(payload.get("failure_containment_rules"), source=f"{path}.failure_containment_rules")
            ),
            concurrency_rules=tuple(
                expect_string_list(payload.get("concurrency_rules"), source=f"{path}.concurrency_rules")
            ),
            evidence_progression_rules=tuple(
                expect_string_list(payload.get("evidence_progression_rules"), source=f"{path}.evidence_progression_rules")
            ),
            model_routing_rules=tuple(
                expect_string_list(payload.get("model_routing_rules"), source=f"{path}.model_routing_rules")
            ),
            methodology_rules=tuple(
                expect_string_list(payload.get("methodology_rules"), source=f"{path}.methodology_rules")
            ),
            markdown_governance=tuple(
                expect_string_list(payload.get("markdown_governance"), source=f"{path}.markdown_governance")
            ),
        )

    def _layer_ref(self, payload: Any, *, source: str) -> AssistantLayerRef:
        if not isinstance(payload, dict):
            raise CatalogValidationError(f"{source} must be an object")
        validate_allowed_fields(payload, self.LAYER_FIELDS, source=source)
        return AssistantLayerRef(
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
