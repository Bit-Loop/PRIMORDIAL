from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial_preprocess.config import load_yaml_file


class PipelineManifestValidationError(ValueError):
    pass


@dataclass(frozen=True)
class RagPreprocessPipelineManifest:
    id: str
    source_path: str
    status: str
    markdown_authoritative: bool
    purpose: tuple[str, ...]
    safety_and_provenance: tuple[str, ...]
    install_commands: tuple[str, ...]
    cli_options: tuple[str, ...]
    pipeline_stages: tuple[str, ...]
    phase_modes: tuple[str, ...]
    output_files: tuple[str, ...]
    generated_markdown_outputs: tuple[str, ...]
    output_rules: tuple[str, ...]
    source_metadata_fields: tuple[str, ...]
    classification_fields: tuple[str, ...]
    chunk_schema_fields: tuple[str, ...]
    override_rules: tuple[str, ...]
    attack_json_rules: tuple[str, ...]
    extraction_contracts: tuple[str, ...]
    troubleshooting_signals: tuple[str, ...]


FIELDS = {
    "id",
    "source_path",
    "status",
    "markdown_authoritative",
    "purpose",
    "safety_and_provenance",
    "install_commands",
    "cli_options",
    "pipeline_stages",
    "phase_modes",
    "output_files",
    "generated_markdown_outputs",
    "output_rules",
    "source_metadata_fields",
    "classification_fields",
    "chunk_schema_fields",
    "override_rules",
    "attack_json_rules",
    "extraction_contracts",
    "troubleshooting_signals",
}


def load_pipeline_manifest(path: Path | str) -> RagPreprocessPipelineManifest:
    path = Path(path)
    payload = load_yaml_file(path)
    _validate_allowed_fields(payload, FIELDS, source=str(path))
    source_path = _text(payload.get("source_path"), source=f"{path}.source_path")
    if not source_path.endswith(".md"):
        raise PipelineManifestValidationError(f"{path}.source_path must reference a Markdown source")
    return RagPreprocessPipelineManifest(
        id=_text(payload.get("id"), source=f"{path}.id"),
        source_path=source_path,
        status=_text(payload.get("status"), source=f"{path}.status"),
        markdown_authoritative=_bool(payload.get("markdown_authoritative"), source=f"{path}.markdown_authoritative"),
        purpose=tuple(_string_list(payload.get("purpose"), source=f"{path}.purpose")),
        safety_and_provenance=tuple(
            _string_list(payload.get("safety_and_provenance"), source=f"{path}.safety_and_provenance")
        ),
        install_commands=tuple(_string_list(payload.get("install_commands"), source=f"{path}.install_commands")),
        cli_options=tuple(_string_list(payload.get("cli_options"), source=f"{path}.cli_options")),
        pipeline_stages=tuple(_string_list(payload.get("pipeline_stages"), source=f"{path}.pipeline_stages")),
        phase_modes=tuple(_string_list(payload.get("phase_modes"), source=f"{path}.phase_modes")),
        output_files=tuple(_string_list(payload.get("output_files"), source=f"{path}.output_files")),
        generated_markdown_outputs=tuple(
            _string_list(payload.get("generated_markdown_outputs"), source=f"{path}.generated_markdown_outputs")
        ),
        output_rules=tuple(_string_list(payload.get("output_rules"), source=f"{path}.output_rules")),
        source_metadata_fields=tuple(
            _string_list(payload.get("source_metadata_fields"), source=f"{path}.source_metadata_fields")
        ),
        classification_fields=tuple(
            _string_list(payload.get("classification_fields"), source=f"{path}.classification_fields")
        ),
        chunk_schema_fields=tuple(
            _string_list(payload.get("chunk_schema_fields"), source=f"{path}.chunk_schema_fields")
        ),
        override_rules=tuple(_string_list(payload.get("override_rules"), source=f"{path}.override_rules")),
        attack_json_rules=tuple(_string_list(payload.get("attack_json_rules"), source=f"{path}.attack_json_rules")),
        extraction_contracts=tuple(
            _string_list(payload.get("extraction_contracts"), source=f"{path}.extraction_contracts")
        ),
        troubleshooting_signals=tuple(
            _string_list(payload.get("troubleshooting_signals"), source=f"{path}.troubleshooting_signals")
        ),
    )


def _validate_allowed_fields(payload: dict[str, Any], allowed: set[str], *, source: str) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise PipelineManifestValidationError(f"{source} contains unknown field(s): {', '.join(unknown)}")


def _text(value: Any, *, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PipelineManifestValidationError(f"{source} must be a non-empty string")
    return value.strip()


def _bool(value: Any, *, source: str) -> bool:
    if not isinstance(value, bool):
        raise PipelineManifestValidationError(f"{source} must be a boolean")
    return value


def _string_list(value: Any, *, source: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise PipelineManifestValidationError(f"{source} must be a list of non-empty strings")
    return [item.strip() for item in value]
