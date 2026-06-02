from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from primordial.core.context.normalization import canonical_rag_domain, normalized_context_key
from primordial.core.domain.enums import ArtifactKind, ScopeProfile
from primordial.core.domain.models import ArtifactRecord, DocumentChunk, Target
from primordial.core.rag.importer_types import CORPUS_TARGET_HANDLE, RagImportOptions


class RagImporterMetadataMixin:
    def _record_matches_filters(self, record: dict[str, Any], options: RagImportOptions) -> bool:
        domain = self._domain(record)
        source_file = str(self._record_value(record, "source_file") or "")
        doc_id = str(self._record_value(record, "doc_id") or self._record_value(record, "source_id") or "")
        domains = {self._canonical_domain(value) for value in options.domains}
        if domains and domain not in domains:
            return False
        if options.source_files and source_file not in options.source_files:
            return False
        return not (options.doc_ids and doc_id not in options.doc_ids)

    def _chunk_from_record(self, record: dict[str, Any], *, target_id: str) -> DocumentChunk:
        text = str(self._record_value(record, "retrieval_text") or self._record_value(record, "text") or "").strip()
        if not text:
            raise ValueError("chunk has no retrieval_text/text")
        source_sha256 = str(self._record_value(record, "source_sha256") or "").strip()
        if not source_sha256:
            raise ValueError("chunk is missing source_sha256")
        chunk_index = self._int(self._record_value(record, "chunk_index"), 0)
        chunk_id = str(self._record_value(record, "chunk_id") or "").strip() or self._derive_chunk_id(record, text, chunk_index)
        domain = self._domain(record)
        return DocumentChunk(
            id=chunk_id,
            target_id=target_id,
            source_artifact_id="pending",
            source_sha256=source_sha256,
            chunk_index=chunk_index,
            title=str(self._record_value(record, "title") or self._record_value(record, "section") or self._record_value(record, "source_file") or chunk_id),
            text=text,
            token_count=self._int(self._record_value(record, "token_estimate"), max(1, len(re.findall(r"\S+", text)))),
            evidence_refs=[],
            metadata=self._metadata(record, domain=domain),
        )

    def _metadata(self, record: dict[str, Any], *, domain: str) -> dict[str, Any]:
        nested = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        metadata = {**self._scrub_raw_content_metadata(nested), **self._base_metadata(record, domain=domain)}
        metadata.update(self._optional_metadata(record))
        if domain == "mitre_attack":
            metadata.update(self._mitre_attack_metadata())
        return metadata

    def _base_metadata(self, record: dict[str, Any], *, domain: str) -> dict[str, Any]:
        raw_text = str(self._record_value(record, "raw_text") or "")
        return {
            "import_source": "primordial-rag-preprocess",
            "citation_id": self._citation_id(record),
            "doc_id": self._record_value(record, "doc_id") or self._record_value(record, "source_id"),
            "source_file": self._record_value(record, "source_file"),
            "source_path": self._record_value(record, "source_path"),
            "source_type": self._record_value(record, "source_type"),
            "domain": domain,
            "original_domain": self._record_value(record, "domain"),
            "secondary_domains": self._list_or_empty(self._record_value(record, "secondary_domains")),
            "corpus_type": domain,
            "authority_level": self._record_value(record, "authority_level"),
            "chunk_type": self._record_value(record, "chunk_type"),
            "section": self._record_value(record, "section"),
            "section_path": self._list_or_empty(self._record_value(record, "section_path")),
            "page_start": self._record_value(record, "page_start"),
            "page_end": self._record_value(record, "page_end"),
            "risk_level": self._record_value(record, "risk_level"),
            "planner_visibility": self._record_value(record, "planner_visibility") or ("taxonomy_only" if domain == "mitre_attack" else "normal"),
            "requires_authorized_scope": self._bool_record_value(record, "requires_authorized_scope", True),
            "scope_gate_required": self._bool_record_value(record, "scope_gate_required", True),
            "requires_operator_approval": self._bool_record_value(record, "requires_operator_approval", False),
            "allowed_use_modes": self._list_or_empty(self._record_value(record, "allowed_use_modes")),
            "allowed_contexts": self._list_or_empty(self._record_value(record, "allowed_contexts")),
            "license_status": self._record_value(record, "license_status"),
            "raw_text_sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest() if raw_text else "",
            "raw_text_stored": False,
            "source_sha256": self._record_value(record, "source_sha256"),
        }

    def _scrub_raw_content_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        raw_content_keys = {"raw_text", "request_body", "response_body", "raw_request", "raw_response"}
        return {
            key: value
            for key, value in metadata.items()
            if normalized_context_key(key) not in raw_content_keys
        }

    def _optional_metadata(self, record: dict[str, Any]) -> dict[str, Any]:
        metadata: dict[str, Any] = {}
        for key in OPTIONAL_METADATA_KEYS:
            value = self._record_value(record, key)
            if value is not None:
                metadata[key] = value
        return metadata

    def _mitre_attack_metadata(self) -> dict[str, Any]:
        return {
            "planner_visibility": "taxonomy_only",
            "allowed_uses": [
                "behavior_classification",
                "framework_mapping",
                "reporting",
                "detection_engineering",
                "mitigation_alignment",
            ],
            "prohibited_uses": [
                "action_selection",
                "scope_expansion",
                "exploit_selection",
                "tool_execution",
                "persistence_or_evasion_workflows",
            ],
        }

    def _citation_id(self, record: dict[str, Any]) -> str:
        explicit = str(self._record_value(record, "citation_id") or "").strip()
        if explicit:
            return explicit if explicit.startswith("rag:") else f"rag:{explicit}"
        chunk_id = str(self._record_value(record, "chunk_id") or "").strip()
        if chunk_id:
            return chunk_id if chunk_id.startswith("rag:") else f"rag:{chunk_id}"
        return self._derived_or_fallback_citation(record)

    def _derived_or_fallback_citation(self, record: dict[str, Any]) -> str:
        text = str(self._record_value(record, "retrieval_text") or self._record_value(record, "text") or "").strip()
        source_sha256 = str(self._record_value(record, "source_sha256") or "").strip()
        if text and source_sha256:
            chunk_index = self._int(self._record_value(record, "chunk_index"), 0)
            return f"rag:{self._derive_chunk_id(record, text, chunk_index)}"
        fallback = str(
            self._record_value(record, "record_id")
            or self._record_value(record, "doc_id")
            or self._record_value(record, "source_id")
            or ""
        ).strip()
        if fallback:
            return fallback if fallback.startswith("rag:") else f"rag:{fallback}"
        return "rag:unknown"

    @staticmethod
    def _record_value(record: dict[str, Any], name: str) -> Any:
        nested = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        for source in (record, nested):
            for raw_key, value in source.items():
                if normalized_context_key(raw_key) == name:
                    return value
        return None

    def _artifact_for_record(self, record: dict[str, Any], *, target_id: str) -> ArtifactRecord:
        source_sha256 = str(self._record_value(record, "source_sha256") or "missing")
        doc_id = str(self._record_value(record, "doc_id") or self._record_value(record, "source_id") or source_sha256[:20])
        source_file = self._record_value(record, "source_file")
        source_path = self._record_value(record, "source_path")
        digest = hashlib.sha256(f"{source_sha256}:{doc_id}".encode("utf-8")).hexdigest()[:20]
        return ArtifactRecord(
            id=f"artifact_rag_{digest}",
            task_id=None,
            target_id=target_id,
            kind=ArtifactKind.RAG_DOCUMENT,
            path=f"rag-preprocess:{source_file or doc_id}",
            sha256=source_sha256,
            size_bytes=0,
            metadata={
                "import_source": "primordial-rag-preprocess",
                "doc_id": doc_id,
                "source_file": source_file,
                "source_path": source_path,
                "domain": self._domain(record),
            },
        )

    def _ensure_corpus_target(self) -> Target:
        existing = self.store.get_target_by_handle(CORPUS_TARGET_HANDLE, ScopeProfile.CORPUS)
        if existing is not None:
            return existing
        target = Target(
            id="target_rag_corpus",
            handle=CORPUS_TARGET_HANDLE,
            display_name="RAG Corpus",
            profile=ScopeProfile.CORPUS,
            in_scope=False,
            metadata={"system_target": True, "purpose": "rag_corpus"},
        )
        self.store.insert_target(target)
        return target

    def _domain(self, record: dict[str, Any]) -> str:
        corpus_type = self._record_value(record, "corpus_type")
        if isinstance(corpus_type, list) and corpus_type:
            value = str(corpus_type[0])
        else:
            value = str(corpus_type or self._record_value(record, "domain") or "general_security")
        return self._canonical_domain(value)

    @staticmethod
    def _canonical_domain(value: str) -> str:
        return canonical_rag_domain(value)

    def _derive_chunk_id(self, record: dict[str, Any], text: str, chunk_index: int) -> str:
        source_sha256 = self._record_value(record, "source_sha256")
        source_id = self._record_value(record, "doc_id") or self._record_value(record, "source_id")
        digest = hashlib.sha256(f"{source_sha256}:{source_id}:{chunk_index}:{self._content_hash(text)}".encode("utf-8")).hexdigest()[:24]
        return f"chunk_{digest}"

    def _content_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _best_record_id(self, raw: str) -> str:
        try:
            data = json.loads(raw)
        except Exception:
            return "invalid_json"
        if not isinstance(data, dict):
            return "invalid_record"
        return str(
            self._record_value(data, "chunk_id")
            or self._record_value(data, "record_id")
            or self._record_value(data, "doc_id")
            or self._record_value(data, "source_id")
            or "unknown"
        )

    def _int(self, value: object, default: int) -> int:
        if isinstance(value, bool):
            return default
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
        return default

    @staticmethod
    def _list_or_empty(value: object) -> list[object]:
        return value if isinstance(value, list) else []

    def _bool_record_value(self, record: dict[str, Any], name: str, default: bool) -> bool:
        value = self._record_value(record, name)
        return bool(value if value is not None else default)


OPTIONAL_METADATA_KEYS = (
    "vuln_id",
    "cve_id",
    "ghsa_ids",
    "osv_ids",
    "aliases",
    "alias",
    "cwe",
    "cwe_ids",
    "cvss",
    "cvss_severity",
    "kev",
    "epss_probability",
    "epss_percentile",
    "affected_vendors",
    "affected_products",
    "affected_packages",
    "affected_versions",
    "fixed_versions",
    "fixed_version_known",
    "package",
    "ecosystem",
    "cpe",
    "purl",
    "source_kind",
    "source_priority",
    "card_type",
    "output_mode",
    "blocked_output_modes",
    "safety_level",
    "content_hash",
    "embedding_policy",
    "source_refs",
    "kind",
    "authority",
    "ingest_allowed",
    "operational_retrieval_allowed",
    "valid_for",
    "invalid_for",
)
