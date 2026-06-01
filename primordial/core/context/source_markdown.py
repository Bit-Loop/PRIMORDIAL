from __future__ import annotations

from urllib.parse import unquote

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.metadata_flags import raw_metadata_value
from primordial.core.context.normalization import normalized_context_key


SOURCE_MARKDOWN_PATH_KEYS = (
    "artifact_path",
    "artifact_paths",
    "file_path",
    "path",
    "source_artifact_path",
    "source_file",
    "source_name",
    "source_path",
    "source_url",
)


def has_source_markdown_path(envelope: ContextEnvelope) -> bool:
    return is_source_markdown_path(envelope.metadata)


def is_source_markdown_context(envelope: ContextEnvelope) -> bool:
    return has_source_markdown_path(envelope) or is_source_markdown_path(raw_metadata_value(envelope, "source_url"))


def is_source_markdown_path(value: object) -> bool:
    if isinstance(value, dict):
        normalized_path_keys = {normalized_context_key(key) for key in SOURCE_MARKDOWN_PATH_KEYS}
        for key, item in value.items():
            if normalized_context_key(key) in normalized_path_keys and is_source_markdown_path(item):
                return True
            if is_source_markdown_path(item):
                return True
        return False
    if isinstance(value, (frozenset, list, set, tuple)):
        return any(is_source_markdown_path(item) for item in value)
    if not value:
        return False
    return any(_path_is_source_markdown(path) for path in _normalized_paths(value))


def _path_is_source_markdown(path: str) -> bool:
    parts = tuple(part for part in path.split("/") if part)
    return len(parts) >= 3 and parts[0:2] == ("docs", "rag_src") and parts[-1].endswith(".md")


def _normalized_paths(value: object) -> tuple[str, ...]:
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
