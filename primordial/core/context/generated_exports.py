from __future__ import annotations

from urllib.parse import unquote

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.normalization import normalized_context_key, normalized_metadata_value


GENERATED_EXPORT_KINDS = frozenset({"generated_export", "export_archive"})
GENERATED_EXPORT_SOURCE_TYPES = frozenset({"generated_export", "export_archive"})
GENERATED_EXPORT_ORIGINS = frozenset({"generated_export", "export_archive"})
GENERATED_EXPORT_CLASSIFICATION_KEYS = ("kind", "kinds", "source_type", "source_types", "origin", "origins")
GENERATED_EXPORT_PATH_KEYS = (
    "artifact_path",
    "artifact_paths",
    "checkpoint_paths",
    "file_path",
    "path",
    "source_artifact_path",
    "source_file",
    "source_name",
    "source_path",
    "source_url",
)
GENERATED_EXPORT_FILE_NAMES = frozenset({"generated-export.md", "generated_export.md", "notion-export.md", "notion_export.md"})


def is_generated_export_context(envelope: ContextEnvelope) -> bool:
    return is_generated_export_record(envelope) or has_generated_export_origin(envelope)


def is_generated_export_record(envelope: ContextEnvelope) -> bool:
    return (
        envelope.kind in GENERATED_EXPORT_KINDS
        or envelope.source_type in GENERATED_EXPORT_SOURCE_TYPES
        or _has_generated_export_classification(envelope.metadata)
    )


def has_generated_export_origin(envelope: ContextEnvelope) -> bool:
    return _has_generated_export_classification(envelope.metadata, keys=("origin",))


def has_generated_export_path(envelope: ContextEnvelope) -> bool:
    return is_generated_export_path(envelope.metadata)


def is_generated_export_metadata(metadata: object) -> bool:
    return _has_generated_export_classification(metadata) or is_generated_export_path(metadata)


def is_generated_export_path(value: object) -> bool:
    if isinstance(value, dict):
        normalized_path_keys = {normalized_context_key(key) for key in GENERATED_EXPORT_PATH_KEYS}
        for key, item in value.items():
            if normalized_context_key(key) in normalized_path_keys and is_generated_export_path(item):
                return True
            if is_generated_export_path(item):
                return True
        return False
    if isinstance(value, (frozenset, list, set, tuple)):
        return any(is_generated_export_path(item) for item in value)
    if not value:
        return False
    return any(_path_has_generated_export_markers(path) for path in _normalized_generated_export_paths(value))


def _path_has_generated_export_markers(path: str) -> bool:
    parts = tuple(part for part in path.split("/") if part)
    name = parts[-1] if parts else ""
    return name in GENERATED_EXPORT_FILE_NAMES or any(
        parts[index : index + 2] == ("findings", "notion") for index in range(max(len(parts) - 1, 0))
    )


def _has_generated_export_classification(
    value: object,
    *,
    keys: tuple[str, ...] = GENERATED_EXPORT_CLASSIFICATION_KEYS,
) -> bool:
    if isinstance(value, dict):
        normalized_keys = {normalized_context_key(key) for key in keys}
        for key, item in value.items():
            if normalized_context_key(key) in normalized_keys and _has_generated_export_classification_value(item):
                return True
            if isinstance(item, dict) and _has_generated_export_classification(item, keys=keys):
                return True
            if isinstance(item, (frozenset, list, set, tuple)) and any(
                _has_generated_export_classification(child, keys=keys) for child in item
            ):
                return True
    if isinstance(value, (frozenset, list, set, tuple)):
        return any(_has_generated_export_classification(item, keys=keys) for item in value)
    return False


def _has_generated_export_classification_value(value: object) -> bool:
    if isinstance(value, (frozenset, list, set, tuple)):
        return any(_has_generated_export_classification_value(item) for item in value)
    return normalized_context_key(value) in GENERATED_EXPORT_ORIGINS


def _normalized_generated_export_paths(value: object) -> tuple[str, ...]:
    path = _decode_url_escapes(str(value).strip().lower()).replace("\\", "/")
    path_only = path.split("?", 1)[0].split("#", 1)[0]
    matrix_parameters_stripped = _strip_matrix_parameters(path_only)
    url_components = path
    for separator in ("?", "#", "&", "=", ";"):
        url_components = url_components.replace(separator, "/")
    return (path_only, matrix_parameters_stripped, url_components)


def _strip_matrix_parameters(path: str) -> str:
    return "/".join(part.split(";", 1)[0] for part in path.split("/"))


def _decode_url_escapes(value: str) -> str:
    decoded = value
    for _ in range(4):
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    return decoded
