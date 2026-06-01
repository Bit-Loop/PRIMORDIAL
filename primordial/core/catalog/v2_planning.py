from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_bool, expect_string_list, load_yaml_file, validate_allowed_fields


@dataclass(frozen=True, slots=True)
class V2PlanningArtifact:
    path: str
    kind: str
    domains: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class V2PlanningManifest:
    id: str
    source_path: str
    status: str
    loaded_by_v1_runtime: bool
    markdown_authoritative: bool
    purpose: tuple[str, ...]
    boundaries: tuple[str, ...]
    artifacts: tuple[V2PlanningArtifact, ...]
    future_integration_gate: tuple[str, ...]


class V2PlanningManifestCatalog:
    FILENAME = "v2_planning.yaml"
    FIELDS = {
        "id",
        "source_path",
        "status",
        "loaded_by_v1_runtime",
        "markdown_authoritative",
        "purpose",
        "boundaries",
        "artifacts",
        "future_integration_gate",
    }
    ARTIFACT_FIELDS = {"path", "kind", "domains"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> V2PlanningManifest:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        source_path = _text(payload.get("source_path"), source=f"{path}.source_path")
        if not source_path.endswith(".md"):
            raise CatalogValidationError(f"{path}.source_path must reference a Markdown source")
        return V2PlanningManifest(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_path=source_path,
            status=_text(payload.get("status"), source=f"{path}.status"),
            loaded_by_v1_runtime=expect_bool(
                payload.get("loaded_by_v1_runtime"), source=f"{path}.loaded_by_v1_runtime"
            ),
            markdown_authoritative=expect_bool(
                payload.get("markdown_authoritative"), source=f"{path}.markdown_authoritative"
            ),
            purpose=tuple(expect_string_list(payload.get("purpose"), source=f"{path}.purpose")),
            boundaries=tuple(expect_string_list(payload.get("boundaries"), source=f"{path}.boundaries")),
            artifacts=tuple(
                self._artifact(item, source=f"{path}.artifacts[{index}]")
                for index, item in enumerate(_list(payload.get("artifacts"), source=f"{path}.artifacts"))
            ),
            future_integration_gate=tuple(
                expect_string_list(payload.get("future_integration_gate"), source=f"{path}.future_integration_gate")
            ),
        )

    def _artifact(self, payload: Any, *, source: str) -> V2PlanningArtifact:
        data = _object(payload, source=source)
        validate_allowed_fields(data, self.ARTIFACT_FIELDS, source=source)
        return V2PlanningArtifact(
            path=_text(data.get("path"), source=f"{source}.path"),
            kind=_text(data.get("kind"), source=f"{source}.kind"),
            domains=tuple(expect_string_list(data.get("domains"), source=f"{source}.domains")),
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
