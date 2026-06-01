from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import (
    CatalogValidationError,
    expect_bool,
    expect_string_list,
    load_yaml_file,
    validate_allowed_fields,
)


@dataclass(frozen=True, slots=True)
class RagAdvisoryDocument:
    source_path: str
    title: str
    source_family: str
    quarantine_path: str
    ingest_allowed: bool
    operational_retrieval_allowed: bool


@dataclass(frozen=True, slots=True)
class RagAdvisoryCorpus:
    id: str
    source_directory: str
    status: str
    authority: str
    source_type: str
    corpus_type: str
    source_markdown_ingest_allowed: bool
    operational_retrieval_allowed: bool
    allowed_use_modes: tuple[str, ...]
    denied_use_modes: tuple[str, ...]
    documents: tuple[RagAdvisoryDocument, ...]


class RagAdvisoryCorpusCatalog:
    FILENAME = "advisory_corpus.yaml"
    FIELDS = {
        "id",
        "source_directory",
        "status",
        "authority",
        "source_type",
        "corpus_type",
        "source_markdown_ingest_allowed",
        "operational_retrieval_allowed",
        "allowed_use_modes",
        "denied_use_modes",
        "documents",
    }
    DOCUMENT_FIELDS = {
        "source_path",
        "title",
        "source_family",
        "quarantine_path",
        "ingest_allowed",
        "operational_retrieval_allowed",
    }

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self) -> RagAdvisoryCorpus:
        path = self.directory / self.FILENAME
        payload = load_yaml_file(path)
        validate_allowed_fields(payload, self.FIELDS, source=str(path))
        source_directory = _text(payload.get("source_directory"), source=f"{path}.source_directory")
        return RagAdvisoryCorpus(
            id=_text(payload.get("id"), source=f"{path}.id"),
            source_directory=source_directory,
            status=_text(payload.get("status"), source=f"{path}.status"),
            authority=_text(payload.get("authority"), source=f"{path}.authority"),
            source_type=_text(payload.get("source_type"), source=f"{path}.source_type"),
            corpus_type=_text(payload.get("corpus_type"), source=f"{path}.corpus_type"),
            source_markdown_ingest_allowed=expect_bool(
                payload.get("source_markdown_ingest_allowed"), source=f"{path}.source_markdown_ingest_allowed"
            ),
            operational_retrieval_allowed=expect_bool(
                payload.get("operational_retrieval_allowed"), source=f"{path}.operational_retrieval_allowed"
            ),
            allowed_use_modes=tuple(expect_string_list(payload.get("allowed_use_modes"), source=f"{path}.allowed_use_modes")),
            denied_use_modes=tuple(expect_string_list(payload.get("denied_use_modes"), source=f"{path}.denied_use_modes")),
            documents=tuple(
                self._document(item, source=f"{path}.documents[{index}]", source_directory=source_directory)
                for index, item in enumerate(_list(payload.get("documents"), source=f"{path}.documents"))
            ),
        )

    def _document(self, payload: Any, *, source: str, source_directory: str) -> RagAdvisoryDocument:
        if not isinstance(payload, dict):
            raise CatalogValidationError(f"{source} must be an object")
        validate_allowed_fields(payload, self.DOCUMENT_FIELDS, source=source)
        source_path = _text(payload.get("source_path"), source=f"{source}.source_path")
        if not source_path.startswith(f"{source_directory}/") or not source_path.endswith(".md"):
            raise CatalogValidationError(f"{source}.source_path must reference Markdown under {source_directory}")
        quarantine_path = _text(payload.get("quarantine_path"), source=f"{source}.quarantine_path")
        expected_quarantine_path = f"runtime/quarantine/markdown/{source_path}"
        if quarantine_path != expected_quarantine_path:
            raise CatalogValidationError(f"{source}.quarantine_path must be {expected_quarantine_path}")
        return RagAdvisoryDocument(
            source_path=source_path,
            title=_text(payload.get("title"), source=f"{source}.title"),
            source_family=_text(payload.get("source_family"), source=f"{source}.source_family"),
            quarantine_path=quarantine_path,
            ingest_allowed=expect_bool(payload.get("ingest_allowed"), source=f"{source}.ingest_allowed"),
            operational_retrieval_allowed=expect_bool(
                payload.get("operational_retrieval_allowed"), source=f"{source}.operational_retrieval_allowed"
            ),
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
