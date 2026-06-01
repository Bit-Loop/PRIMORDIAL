from __future__ import annotations

import re
from typing import Any

from primordial.core.context.normalization import (
    canonical_rag_domain,
    metadata_value,
    normalized_metadata_value,
)
from primordial.core.domain.enums import AgentRole
from primordial.core.domain.models import Task
from primordial.core.rag.context_models import RagContextPack, RagContextSource
from primordial.core.rag.documents import RagContextItem


class RagContextSourceMixin:
    def _source_from_payload(self, item: dict[str, Any]) -> RagContextSource | None:
        chunk_id = str(item.get("chunk_id") or item.get("id") or "").strip()
        if not chunk_id:
            return None
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        title = str(
            metadata_value(item, "title")
            or metadata_value(metadata, "title")
            or metadata_value(item, "source_file")
            or metadata_value(item, "source_path")
            or metadata_value(metadata, "source_file")
            or metadata_value(metadata, "source_path")
            or chunk_id
        )
        source_file = str(
            metadata_value(item, "source_file")
            or metadata_value(item, "source_path")
            or metadata_value(metadata, "source_file")
            or metadata_value(metadata, "source_path")
            or ""
        )
        section = str(metadata_value(item, "section") or metadata_value(metadata, "section") or "")
        page_start = self._optional_int(metadata_value(item, "page_start") or metadata_value(metadata, "page_start"))
        page_end = self._optional_int(metadata_value(item, "page_end") or metadata_value(metadata, "page_end"))
        source_display = str(
            metadata_value(item, "source_display")
            or metadata_value(metadata, "source_display")
            or self._source_display(
                title=title,
                source_file=source_file,
                section=section,
                page_start=page_start,
                page_end=page_end,
            )
        )
        return RagContextSource(
            chunk_id=chunk_id,
            citation_id=self._normalize_citation_id(
                str(metadata_value(item, "citation_id") or metadata_value(metadata, "citation_id") or chunk_id)
            ),
            source_display=source_display,
            source_file=source_file,
            title=title,
            section=section,
            page_start=page_start,
            page_end=page_end,
            domain=canonical_rag_domain(
                metadata_value(item, "domain")
                or metadata_value(metadata, "domain")
                or metadata_value(item, "corpus_type")
                or metadata_value(metadata, "corpus_type")
            ),
            risk_level=normalized_metadata_value(item, "risk_level") or normalized_metadata_value(metadata, "risk_level"),
            planner_visibility=normalized_metadata_value(item, "planner_visibility")
            or normalized_metadata_value(metadata, "planner_visibility"),
            usage_policy=self._usage_policy_from_metadata(self._usage_metadata(item, metadata)),
            excerpt=self._excerpt(
                str(
                    metadata_value(item, "text")
                    or metadata_value(item, "retrieval_text")
                    or metadata_value(item, "excerpt")
                    or metadata_value(item, "raw_text")
                    or metadata_value(metadata, "text")
                    or metadata_value(metadata, "retrieval_text")
                    or metadata_value(metadata, "excerpt")
                    or metadata_value(metadata, "raw_text")
                    or ""
                )
            ),
            score=float(item.get("score") or 0.0),
        )

    def _usage_metadata(self, item: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
        return {
            **metadata,
            "domain": metadata_value(item, "domain") or metadata_value(metadata, "domain"),
            "corpus_type": metadata_value(item, "corpus_type") or metadata_value(metadata, "corpus_type"),
            "planner_visibility": metadata_value(item, "planner_visibility")
            or metadata_value(metadata, "planner_visibility"),
            "risk_level": metadata_value(item, "risk_level") or metadata_value(metadata, "risk_level"),
            "requires_operator_approval": metadata_value(item, "requires_operator_approval")
            or metadata_value(metadata, "requires_operator_approval"),
        }

    def _source_for_item(self, item: RagContextItem) -> RagContextSource:
        chunk = item.chunk
        metadata = chunk.metadata
        title = str(chunk.title or metadata_value(metadata, "title") or metadata_value(metadata, "source_file") or chunk.id)
        source_file = str(metadata_value(metadata, "source_file") or metadata_value(metadata, "source_path") or "")
        section = str(metadata_value(metadata, "section") or "")
        page_start = self._optional_int(metadata_value(metadata, "page_start"))
        page_end = self._optional_int(metadata_value(metadata, "page_end"))
        source_display = str(
            metadata_value(metadata, "source_display")
            or self._source_display(
                title=title,
                source_file=source_file,
                section=section,
                page_start=page_start,
                page_end=page_end,
            )
        )
        return RagContextSource(
            chunk_id=chunk.id,
            citation_id=self._citation_id_for_chunk(chunk),
            source_display=source_display,
            source_file=source_file,
            title=title,
            section=section,
            page_start=page_start,
            page_end=page_end,
            domain=canonical_rag_domain(metadata_value(metadata, "domain") or metadata_value(metadata, "corpus_type")),
            risk_level=normalized_metadata_value(metadata, "risk_level"),
            planner_visibility=normalized_metadata_value(metadata, "planner_visibility"),
            usage_policy=self._usage_policy_from_metadata(metadata),
            excerpt=self._excerpt(chunk.text),
            score=item.score,
        )

    def _citation_id_for_chunk(self, chunk: object) -> str:
        metadata = getattr(chunk, "metadata", {})
        citation_id = str(metadata_value(metadata, "citation_id") or "").strip()
        if not citation_id or citation_id.lower() in {"rag:none", "rag:null", "rag:unknown"}:
            citation_id = str(getattr(chunk, "id"))
        return self._normalize_citation_id(citation_id)

    def _normalize_citation_id(self, citation_id: str) -> str:
        clean = citation_id.strip()
        if not clean or clean.lower() in {"rag:none", "rag:null", "rag:unknown"}:
            clean = "unknown"
        if clean.lower().startswith("rag:"):
            return f"rag:{clean[4:].strip()}"
        return f"rag:{clean}"

    def _source_display(
        self,
        *,
        title: str,
        source_file: str,
        section: str,
        page_start: int | None,
        page_end: int | None,
    ) -> str:
        label = section or title or source_file or "RAG source"
        location = ""
        if page_start and page_end and page_end != page_start:
            location = f" pp. {page_start}-{page_end}"
        elif page_start:
            location = f" p. {page_start}"
        if source_file and source_file not in label:
            return f"{label} ({source_file}{location})"
        return f"{label}{location}"

    def _role_name(self, role: str | AgentRole | None, task: Task | None) -> str:
        if role is not None:
            return str(role.value if isinstance(role, AgentRole) else role).strip().lower()
        if task is not None:
            if task.role == AgentRole.CODE_WORKER:
                return "local_code"
            if task.role in {AgentRole.EXPLOITATION_WORKER, AgentRole.CHAINING_WORKER, AgentRole.BEHAVIOR_VERIFIER}:
                return "local_deep"
            if task.role == AgentRole.MEMORY_WORKER:
                return "local_compact"
        return "local_fast"

    def _add_pack_warnings(self, pack: RagContextPack) -> None:
        if pack.omitted_sources:
            pack.warnings.append(f"{len(pack.omitted_sources)} RAG source(s) were withheld by role/purpose policy")
        if not pack.chunks:
            pack.warnings.append("no admissible RAG chunks for this role/purpose")

    def _excerpt(self, text: str, *, max_chars: int = 360) -> str:
        excerpt = re.sub(r"\s+", " ", text or "").strip()
        if len(excerpt) > max_chars:
            return excerpt[:max_chars].rstrip() + "..."
        return excerpt

    def _optional_int(self, value: object) -> int | None:
        try:
            if value is None or value == "":
                return None
            return int(value)
        except (TypeError, ValueError):
            return None
