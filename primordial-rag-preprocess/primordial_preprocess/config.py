from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - dependency error path
    yaml = None


@dataclass(frozen=True)
class ChunkPolicy:
    target_chars: int = 3600
    overlap_chars: int = 500


@dataclass(frozen=True)
class CorpusPolicy:
    extract_open_public_sources: bool = True
    extract_attack_json: bool = True
    extract_markdown: bool = True
    extract_html: bool = False
    extract_known_docs_html: bool = True
    extract_commercial_unknown_license: bool = False
    extract_restricted_security_books: bool = False
    allow_operator_overrides: bool = True
    allow_duplicate_extraction: bool = False
    prefer_docling: bool = True
    docling_only: bool = True
    fallback_extractors_enabled: bool = False
    docling_allow_ocr: bool = False
    docling_chunker: str = "hybrid"
    epub_conversion: str = "pandoc_only"
    vlm_profile_extraction: bool = False
    overwrite_existing: bool = False
    chunking: ChunkPolicy = field(default_factory=ChunkPolicy)
    allowed_contexts_default: list[str] = field(
        default_factory=lambda: ["owned_lab", "ctf", "authorized_security_research"]
    )
    known_docs_html_patterns: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SourceOverride:
    sha256: str
    license_status: str | None = None
    extraction_allowed: bool | None = None
    notes: str = ""


def load_yaml_file(path: Path | str) -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return {}
    if yaml is None:
        raise RuntimeError("pyyaml is required to load YAML config")
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"YAML config must be a mapping: {path}")
    return payload


def load_policy(path: Path | str) -> CorpusPolicy:
    payload = load_yaml_file(path)
    chunking = payload.get("chunking", {}) if isinstance(payload.get("chunking"), dict) else {}
    return CorpusPolicy(
        extract_open_public_sources=bool(payload.get("extract_open_public_sources", True)),
        extract_attack_json=bool(payload.get("extract_attack_json", True)),
        extract_markdown=bool(payload.get("extract_markdown", True)),
        extract_html=bool(payload.get("extract_html", False)),
        extract_known_docs_html=bool(payload.get("extract_known_docs_html", True)),
        extract_commercial_unknown_license=bool(payload.get("extract_commercial_unknown_license", False)),
        extract_restricted_security_books=bool(payload.get("extract_restricted_security_books", False)),
        allow_operator_overrides=bool(payload.get("allow_operator_overrides", True)),
        allow_duplicate_extraction=bool(payload.get("allow_duplicate_extraction", False)),
        prefer_docling=bool(payload.get("prefer_docling", True)),
        docling_only=bool(payload.get("docling_only", True)),
        fallback_extractors_enabled=bool(payload.get("fallback_extractors_enabled", False)),
        docling_allow_ocr=bool(payload.get("docling_allow_ocr", False)),
        docling_chunker=str(payload.get("docling_chunker", "hybrid")),
        epub_conversion=str(payload.get("epub_conversion", "pandoc_only")),
        vlm_profile_extraction=bool(payload.get("vlm_profile_extraction", False)),
        overwrite_existing=bool(payload.get("overwrite_existing", False)),
        chunking=ChunkPolicy(
            target_chars=int(chunking.get("target_chars", 3600)),
            overlap_chars=int(chunking.get("overlap_chars", 500)),
        ),
        allowed_contexts_default=[str(item) for item in payload.get("allowed_contexts_default", [])]
        or ["owned_lab", "ctf", "authorized_security_research"],
        known_docs_html_patterns=[str(item).lower() for item in payload.get("known_docs_html_patterns", [])],
    )


def load_overrides(path: Path | str | None) -> dict[str, SourceOverride]:
    if not path:
        return {}
    payload = load_yaml_file(path)
    sources = payload.get("sources", {})
    if not isinstance(sources, dict):
        raise ValueError("source overrides must contain a 'sources' mapping")
    overrides: dict[str, SourceOverride] = {}
    for sha256, values in sources.items():
        if not isinstance(values, dict):
            continue
        overrides[str(sha256)] = SourceOverride(
            sha256=str(sha256),
            license_status=str(values["license_status"]) if values.get("license_status") is not None else None,
            extraction_allowed=bool(values["extraction_allowed"])
            if values.get("extraction_allowed") is not None
            else None,
            notes=str(values.get("notes") or ""),
        )
    return overrides
