from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_bool, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class ProjectManifest:
    id: str
    runtime_model: str
    domains: tuple[str, ...]
    authority_sources: tuple[str, ...]
    core_principles: tuple[str, ...]
    implemented_surfaces: tuple[str, ...]
    cli_commands: tuple[str, ...]
    runtime_directories: tuple[str, ...]
    required_environment: tuple[str, ...]
    policy_environment: tuple[str, ...]
    agent_chat_environment: tuple[str, ...]
    hard_boundaries: tuple[str, ...]
    poc_execution_gate: tuple[str, ...]
    markdown_authoritative: bool


class ProjectManifestCatalog:
    FILENAME = "primordial.yaml"
    FIELDS = {
        "id",
        "runtime_model",
        "domains",
        "authority_sources",
        "core_principles",
        "implemented_surfaces",
        "cli_commands",
        "runtime_directories",
        "required_environment",
        "policy_environment",
        "agent_chat_environment",
        "hard_boundaries",
        "poc_execution_gate",
        "markdown_authoritative",
    }

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> ProjectManifest:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        return ProjectManifest(
            id=_text(payload.get("id"), source=f"{path}.id"),
            runtime_model=_text(payload.get("runtime_model"), source=f"{path}.runtime_model"),
            domains=tuple(expect_string_list(payload.get("domains"), source=f"{path}.domains")),
            authority_sources=tuple(expect_string_list(payload.get("authority_sources"), source=f"{path}.authority_sources")),
            core_principles=tuple(expect_string_list(payload.get("core_principles"), source=f"{path}.core_principles")),
            implemented_surfaces=tuple(
                expect_string_list(payload.get("implemented_surfaces"), source=f"{path}.implemented_surfaces")
            ),
            cli_commands=tuple(expect_string_list(payload.get("cli_commands"), source=f"{path}.cli_commands")),
            runtime_directories=tuple(expect_string_list(payload.get("runtime_directories"), source=f"{path}.runtime_directories")),
            required_environment=tuple(
                expect_string_list(payload.get("required_environment"), source=f"{path}.required_environment")
            ),
            policy_environment=tuple(expect_string_list(payload.get("policy_environment"), source=f"{path}.policy_environment")),
            agent_chat_environment=tuple(
                expect_string_list(payload.get("agent_chat_environment"), source=f"{path}.agent_chat_environment")
            ),
            hard_boundaries=tuple(expect_string_list(payload.get("hard_boundaries"), source=f"{path}.hard_boundaries")),
            poc_execution_gate=tuple(
                expect_string_list(payload.get("poc_execution_gate"), source=f"{path}.poc_execution_gate")
            ),
            markdown_authoritative=expect_bool(payload.get("markdown_authoritative"), source=f"{path}.markdown_authoritative"),
        )


def _text(value: Any, *, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogValidationError(f"{source} must be a non-empty string")
    return value.strip()
