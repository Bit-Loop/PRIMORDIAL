from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial_preprocess.config import load_yaml_file


class AgentPolicyValidationError(ValueError):
    pass


@dataclass(frozen=True)
class RagPreprocessAgentPolicy:
    id: str
    source_path: str
    status: str
    markdown_authoritative: bool
    boundaries: tuple[str, ...]
    defaults: tuple[str, ...]
    parser_constraints: tuple[str, ...]
    extraction_constraints: tuple[str, ...]
    explicit_operator_toggles: tuple[str, ...]
    restricted_material: tuple[str, ...]


FIELDS = {
    "id",
    "source_path",
    "status",
    "markdown_authoritative",
    "boundaries",
    "defaults",
    "parser_constraints",
    "extraction_constraints",
    "explicit_operator_toggles",
    "restricted_material",
}


def load_agent_policy(path: Path | str) -> RagPreprocessAgentPolicy:
    path = Path(path)
    payload = load_yaml_file(path)
    _validate_allowed_fields(payload, FIELDS, source=str(path))
    source_path = _text(payload.get("source_path"), source=f"{path}.source_path")
    if not source_path.endswith(".md"):
        raise AgentPolicyValidationError(f"{path}.source_path must reference a Markdown source")
    return RagPreprocessAgentPolicy(
        id=_text(payload.get("id"), source=f"{path}.id"),
        source_path=source_path,
        status=_text(payload.get("status"), source=f"{path}.status"),
        markdown_authoritative=_bool(payload.get("markdown_authoritative"), source=f"{path}.markdown_authoritative"),
        boundaries=tuple(_string_list(payload.get("boundaries"), source=f"{path}.boundaries")),
        defaults=tuple(_string_list(payload.get("defaults"), source=f"{path}.defaults")),
        parser_constraints=tuple(_string_list(payload.get("parser_constraints"), source=f"{path}.parser_constraints")),
        extraction_constraints=tuple(
            _string_list(payload.get("extraction_constraints"), source=f"{path}.extraction_constraints")
        ),
        explicit_operator_toggles=tuple(
            _string_list(payload.get("explicit_operator_toggles"), source=f"{path}.explicit_operator_toggles")
        ),
        restricted_material=tuple(
            _string_list(payload.get("restricted_material"), source=f"{path}.restricted_material")
        ),
    )


def _validate_allowed_fields(payload: dict[str, Any], allowed: set[str], *, source: str) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise AgentPolicyValidationError(f"{source} contains unknown field(s): {', '.join(unknown)}")


def _text(value: Any, *, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AgentPolicyValidationError(f"{source} must be a non-empty string")
    return value.strip()


def _bool(value: Any, *, source: str) -> bool:
    if not isinstance(value, bool):
        raise AgentPolicyValidationError(f"{source} must be a boolean")
    return value


def _string_list(value: Any, *, source: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise AgentPolicyValidationError(f"{source} must be a list of non-empty strings")
    return [item.strip() for item in value]
