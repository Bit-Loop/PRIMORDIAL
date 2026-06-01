from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_bool, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class MethodologyExample:
    id: str
    source_path: str
    title: str
    assumptions: tuple[str, ...]
    steps: tuple[str, ...]
    promotion_requirements: tuple[str, ...]
    compiler_input_format: str
    generated_artifact_path: str
    proposal_semantics: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MethodologyExamples:
    id: str
    status: str
    authority: str
    markdown_authoritative: bool
    boundaries: tuple[str, ...]
    examples: tuple[MethodologyExample, ...]


class MethodologyExamplesCatalog:
    FILENAME = "methodology_examples.yaml"
    FIELDS = {"id", "status", "authority", "markdown_authoritative", "boundaries", "examples"}
    EXAMPLE_FIELDS = {
        "id",
        "source_path",
        "title",
        "assumptions",
        "steps",
        "promotion_requirements",
        "compiler_input_format",
        "generated_artifact_path",
        "proposal_semantics",
    }

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> MethodologyExamples:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        return MethodologyExamples(
            id=_text(payload.get("id"), source=f"{path}.id"),
            status=_text(payload.get("status"), source=f"{path}.status"),
            authority=_text(payload.get("authority"), source=f"{path}.authority"),
            markdown_authoritative=expect_bool(
                payload.get("markdown_authoritative"), source=f"{path}.markdown_authoritative"
            ),
            boundaries=tuple(expect_string_list(payload.get("boundaries"), source=f"{path}.boundaries")),
            examples=tuple(
                self._example(item, source=f"{path}.examples[{index}]")
                for index, item in enumerate(_list(payload.get("examples"), source=f"{path}.examples"))
            ),
        )

    def _example(self, payload: Any, *, source: str) -> MethodologyExample:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.EXAMPLE_FIELDS, source=source)
        source_path = _text(data.get("source_path"), source=f"{source}.source_path")
        if not source_path.endswith(".md"):
            raise CatalogValidationError(f"{source}.source_path must reference a Markdown source")
        return MethodologyExample(
            id=_text(data.get("id"), source=f"{source}.id"),
            source_path=source_path,
            title=_text(data.get("title"), source=f"{source}.title"),
            assumptions=tuple(expect_string_list(data.get("assumptions"), source=f"{source}.assumptions")),
            steps=tuple(expect_string_list(data.get("steps"), source=f"{source}.steps")),
            promotion_requirements=tuple(
                expect_string_list(data.get("promotion_requirements"), source=f"{source}.promotion_requirements")
            ),
            compiler_input_format=_text(data.get("compiler_input_format"), source=f"{source}.compiler_input_format"),
            generated_artifact_path=_text(
                data.get("generated_artifact_path"), source=f"{source}.generated_artifact_path"
            ),
            proposal_semantics=tuple(
                expect_string_list(data.get("proposal_semantics"), source=f"{source}.proposal_semantics")
            ),
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
