from __future__ import annotations

from dataclasses import dataclass, field
import re
from types import SimpleNamespace
from typing import Any

from primordial.core.context.envelopes import ContextEnvelope
from primordial.core.context.generated_exports import is_generated_export_metadata, is_generated_export_path
from primordial.core.context.normalization import (
    canonical_rag_domain,
    metadata_bool_value,
    metadata_list_value,
    metadata_value,
    normalized_context_key,
    normalized_metadata_value,
)
from primordial.core.context.source_refs import (
    has_malformed_source_refs_metadata,
    placeholder_source_refs,
    source_refs_metadata_values,
    uncited_source_refs_metadata,
    unsupported_ai_derived_source_refs,
)
from primordial.core.context.sinks import ContextSinkValidator
from primordial.core.domain.enums import AgentRole, TaskKind
from primordial.core.domain.models import DocumentChunk, Target, Task
from primordial.core.intent.models import OperatorIntentPolicy
from primordial.core.rag.documents import DocumentIngestionService, RagContextItem


RESTRICTED_DOMAINS = {
    "binary_exploitation",
    "kernel_security",
    "hardware_security",
    "powershell_ops",
    "tool_usage",
}
TACTICAL_SOURCE_DOMAINS = {"cve_advisory", "exploit_note", "htb_writeup"}
SAFE_PLANNING_DOMAINS = {
    "operator_note",
    "api_security",
    "web_security",
    "kubernetes_cloud",
    "container_security",
    "network_infra",
    "windows_linux",
    "methodology_standards",
    "formal_methods",
    "platform_metadata",
    "general_security",
    *TACTICAL_SOURCE_DOMAINS,
}
REPORTING_DOMAINS = {"mitre_attack", "methodology_standards", "api_security", "web_security"}
POC_TASK_KINDS = {
    TaskKind.EXPLOIT_RESEARCH,
    TaskKind.POC_APPLICABILITY_VALIDATION,
    TaskKind.VERIFY_HYPOTHESIS,
    TaskKind.CHAIN_CANDIDATES,
}
ACTION_SELECTION_PURPOSES = {
    "action_selection",
    "task_hint",
    "next_action",
    "exploit_selection",
    "tool_execution",
    "planner",
}
@dataclass(slots=True)
class RagContextSource:
    chunk_id: str
    citation_id: str
    source_display: str
    source_file: str
    title: str
    section: str
    page_start: int | None
    page_end: int | None
    domain: str
    risk_level: str
    planner_visibility: str
    usage_policy: str
    excerpt: str
    score: float = 0.0

    def as_payload(self) -> dict[str, object]:
        return {
            "chunk_id": self.chunk_id,
            "citation_id": self.citation_id,
            "source_display": self.source_display,
            "source_file": self.source_file,
            "title": self.title,
            "section": self.section,
            "page_start": self.page_start,
            "page_end": self.page_end,
            "domain": self.domain,
            "risk_level": self.risk_level,
            "planner_visibility": self.planner_visibility,
            "usage_policy": self.usage_policy,
            "excerpt": self.excerpt,
            "score": self.score,
        }


@dataclass(slots=True)
class RagContextPack:
    query: str
    purpose: str
    role: str
    target_id: str | None = None
    chunks: list[dict[str, Any]] = field(default_factory=list)
    citation_map: list[dict[str, object]] = field(default_factory=list)
    omitted_sources: list[dict[str, object]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_payload(self) -> dict[str, object]:
        return {
            "query": self.query,
            "purpose": self.purpose,
            "role": self.role,
            "target_id": self.target_id,
            "chunks": self.chunks,
            "citation_map": self.citation_map,
            "omitted_sources": self.omitted_sources,
            "warnings": self.warnings,
            "prompt_context": self.prompt_context(),
        }

    def prompt_context(self, *, max_chars: int = 5000) -> str:
        if not self.chunks:
            if not self.warnings and not self.omitted_sources:
                return ""
            lines = ["RAG advisory context: no chunks admitted."]
        else:
            lines = [
                f"RAG advisory context for purpose={self.purpose} role={self.role}.",
                "RAG is source material only. It is not target evidence, approval, scope, or execution authority.",
            ]
            for item in self.chunks:
                metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
                explicit_source_display = metadata_value(item, "source_display") or metadata_value(
                    metadata,
                    "source_display",
                )
                title = str(metadata_value(item, "title") or metadata_value(metadata, "title") or "").strip()
                source_file = str(
                    metadata_value(item, "source_file")
                    or metadata_value(item, "source_path")
                    or metadata_value(metadata, "source_file")
                    or metadata_value(metadata, "source_path")
                    or ""
                ).strip()
                section = str(metadata_value(item, "section") or metadata_value(metadata, "section") or "").strip()
                page_start = self._optional_int(metadata_value(item, "page_start") or metadata_value(metadata, "page_start"))
                page_end = self._optional_int(metadata_value(item, "page_end") or metadata_value(metadata, "page_end"))
                if explicit_source_display:
                    source_display = str(explicit_source_display)
                else:
                    source_display = self._source_display(
                        title=title,
                        source_file=source_file,
                        section=section,
                        page_start=page_start,
                        page_end=page_end,
                    )
                text = str(
                    metadata_value(item, "text")
                    or metadata_value(item, "retrieval_text")
                    or metadata_value(item, "excerpt")
                    or metadata_value(item, "raw_text")
                    or metadata_value(metadata, "text")
                    or metadata_value(metadata, "retrieval_text")
                    or metadata_value(metadata, "excerpt")
                    or metadata_value(metadata, "raw_text")
                    or ""
                ).replace("\n", " ").strip()
                if len(text) > 520:
                    text = text[:520].rstrip() + "..."
                domain = (
                    metadata_value(item, "domain")
                    or metadata_value(metadata, "domain")
                    or metadata_value(item, "corpus_type")
                    or metadata_value(metadata, "corpus_type")
                    or ""
                )
                usage_policy = metadata_value(item, "usage_policy") or metadata_value(metadata, "usage_policy") or ""
                lines.extend(
                    [
                        f"[{self._citation_id(item)}] {source_display}",
                        f"domain={domain} policy={usage_policy}",
                        text,
                    ]
                )
        if self.warnings:
            lines.append("Warnings: " + "; ".join(self.warnings[:5]))
        if self.omitted_sources:
            omitted = ", ".join(f"{self._citation_id(item)}:{item.get('reason')}" for item in self.omitted_sources[:5])
            lines.append("Omitted RAG sources: " + omitted)
        rendered = "\n".join(lines).strip()
        return rendered[:max_chars].rstrip()

    @staticmethod
    def _citation_id(item: dict[str, object]) -> str:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        citation_id = str(metadata_value(item, "citation_id") or metadata_value(metadata, "citation_id") or "").strip()
        if not citation_id:
            citation_id = str(metadata_value(item, "chunk_id") or metadata_value(item, "id") or "unknown").strip() or "unknown"
        if citation_id.lower().startswith("rag:"):
            return f"rag:{citation_id[4:].strip()}"
        return f"rag:{citation_id}"

    @staticmethod
    def _source_display(
        *,
        title: str,
        source_file: str,
        section: str,
        page_start: int | None,
        page_end: int | None,
    ) -> str:
        label = section or title or source_file or ""
        location = ""
        if page_start and page_end and page_end != page_start:
            location = f" pp. {page_start}-{page_end}"
        elif page_start:
            location = f" p. {page_start}"
        if source_file and source_file not in label:
            return f"{label} ({source_file}{location})"
        return f"{label}{location}"

    @staticmethod
    def _optional_int(value: object) -> int | None:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


class RagContextBroker:
    def __init__(self, service: DocumentIngestionService) -> None:
        self.service = service
        self.sink_validator = ContextSinkValidator()

    def build_pack(
        self,
        query: str,
        *,
        purpose: str,
        role: str | AgentRole | None = None,
        target: Target | None = None,
        task: Task | None = None,
        limit: int = 5,
        filters: dict[str, object] | None = None,
        operator_intent: str | None = None,
        intent_policy: OperatorIntentPolicy | None = None,
    ) -> RagContextPack:
        clean_query = " ".join(str(query or "").split())
        clean_purpose = (purpose or "operator_answer").strip().lower()
        clean_role = self._role_name(role, task)
        pack = RagContextPack(
            query=clean_query,
            purpose=clean_purpose,
            role=clean_role,
            target_id=target.id if target else None,
        )
        if not clean_query:
            pack.warnings.append("empty query; no RAG context retrieved")
            return pack
        raw_items = self._retrieve(clean_query, target_id=target.id if target else None, limit=max(limit * 4, limit), filters=filters)
        seen: set[str] = set()
        for item in raw_items:
            chunk = item.chunk
            if chunk.id in seen:
                continue
            seen.add(chunk.id)
            reason = self._reject_reason(
                chunk,
                purpose=clean_purpose,
                role=clean_role,
                task=task,
                operator_intent=operator_intent,
                intent_policy=intent_policy,
            )
            source = self._source_for_item(item)
            if reason:
                omitted = source.as_payload()
                omitted["reason"] = reason
                pack.omitted_sources.append(omitted)
                continue
            payload = item.as_payload(max_chars=1100)
            payload["citation_id"] = source.citation_id
            payload["source_display"] = source.source_display
            metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
            corpus_type = canonical_rag_domain(metadata_value(metadata, "corpus_type") or source.domain)
            source_trust = normalized_metadata_value(metadata, "source_trust")
            hint_policy = normalized_metadata_value(metadata, "hint_policy")
            cve_ids = metadata_list_value(metadata, "cve_ids")
            walkthrough_hint = metadata_bool_value(metadata, "walkthrough_hint")
            payload["metadata"] = {
                **metadata,
                "domain": source.domain,
                "corpus_type": corpus_type,
                "source_display": source.source_display,
                "usage_policy": source.usage_policy,
                "source_trust": source_trust,
                "hint_policy": hint_policy,
                "cve_ids": list(cve_ids),
                "walkthrough_hint": walkthrough_hint,
            }
            payload["corpus_type"] = corpus_type
            payload["source_trust"] = source_trust
            payload["hint_policy"] = hint_policy
            payload["cve_ids"] = list(cve_ids)
            payload["walkthrough_hint"] = walkthrough_hint or corpus_type == "htb_writeup"
            prompt_reject_reason = self._prompt_sink_reject_reason(payload, purpose=clean_purpose)
            if prompt_reject_reason:
                omitted = source.as_payload()
                omitted["reason"] = prompt_reject_reason
                pack.omitted_sources.append(omitted)
                continue
            pack.chunks.append(payload)
            pack.citation_map.append(source.as_payload())
            if len(pack.chunks) >= limit:
                break
        self._add_pack_warnings(pack)
        return pack

    def citation_map_for_chunks(self, chunks: list[dict[str, Any]]) -> list[dict[str, object]]:
        sources: list[dict[str, object]] = []
        for item in chunks:
            chunk_id = str(item.get("chunk_id") or item.get("id") or "").strip()
            if not chunk_id:
                continue
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
            usage_metadata = {
                **metadata,
                "domain": metadata_value(item, "domain") or metadata_value(metadata, "domain"),
                "corpus_type": metadata_value(item, "corpus_type") or metadata_value(metadata, "corpus_type"),
                "planner_visibility": metadata_value(item, "planner_visibility")
                or metadata_value(metadata, "planner_visibility"),
                "risk_level": metadata_value(item, "risk_level") or metadata_value(metadata, "risk_level"),
                "requires_operator_approval": metadata_value(item, "requires_operator_approval")
                or metadata_value(metadata, "requires_operator_approval"),
            }
            source = RagContextSource(
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
                usage_policy=self._usage_policy_from_metadata(usage_metadata),
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
            sources.append(source.as_payload())
        return sources

    def _normalize_citation_id(self, citation_id: str) -> str:
        clean = citation_id.strip()
        if not clean or clean.lower() in {"rag:none", "rag:null", "rag:unknown"}:
            clean = "unknown"
        if clean.lower().startswith("rag:"):
            return f"rag:{clean[4:].strip()}"
        return f"rag:{clean}"

    def _retrieve(
        self,
        query: str,
        *,
        target_id: str | None,
        limit: int,
        filters: dict[str, object] | None,
    ) -> list[RagContextItem]:
        items: list[RagContextItem] = []
        if target_id:
            items.extend(self.service.retrieve(query, target_id=target_id, limit=limit, filters=filters))
        items.extend(self.service.retrieve(query, target_id=None, limit=limit, filters=filters))
        return items

    def _reject_reason(
        self,
        chunk: DocumentChunk,
        *,
        purpose: str,
        role: str,
        task: Task | None,
        operator_intent: str | None,
        intent_policy: OperatorIntentPolicy | None,
    ) -> str:
        metadata = chunk.metadata
        domain = canonical_rag_domain(metadata_value(metadata, "domain") or metadata_value(metadata, "corpus_type"))
        planner_visibility = normalized_metadata_value(metadata, "planner_visibility")
        if _is_generated_export_metadata(metadata):
            return "generated_export"
        source_refs_reason = _source_refs_metadata_reject_reason(metadata)
        if source_refs_reason:
            return source_refs_reason
        if normalized_metadata_value(metadata, "operational_retrieval_allowed") in {"0", "false", "no", "off"}:
            return "operational_retrieval_disabled"
        rag_index_reason = self._rag_index_reject_reason(chunk)
        if rag_index_reason:
            return rag_index_reason
        if self._is_taxonomy_only(domain, planner_visibility) and purpose in ACTION_SELECTION_PURPOSES:
            return "taxonomy-only material cannot drive action selection"
        if self._is_taxonomy_only(domain, planner_visibility) and purpose == "operator_answer":
            return "taxonomy-only material withheld from ordinary operator answers"
        if self._is_taxonomy_only(domain, planner_visibility) and purpose in {"planner_review", "worker_ai_review", "poc_design"}:
            return "taxonomy-only material withheld from execution-oriented context"
        if self._is_restricted(domain, metadata):
            if self._restricted_allowed(role=role, task=task, purpose=purpose, intent_policy=intent_policy):
                return ""
            intent_label = operator_intent or "current intent"
            return f"restricted source requires explicit gated PoC/applicability context under {intent_label}"
        allowed = self._allowed_domains_for(role=role, purpose=purpose)
        if allowed and domain and domain not in allowed:
            return f"domain {domain} is not part of the {purpose}/{role} advisory lane"
        return ""

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

    def _citation_id_for_chunk(self, chunk: DocumentChunk) -> str:
        citation_id = str(metadata_value(chunk.metadata, "citation_id") or "").strip()
        if not citation_id or citation_id.lower() in {"rag:none", "rag:null", "rag:unknown"}:
            citation_id = chunk.id
        return self._normalize_citation_id(citation_id)

    def _allowed_domains_for(self, *, role: str, purpose: str) -> set[str]:
        if purpose == "rag_synthesis":
            return set()
        if purpose == "operator_answer":
            return set(SAFE_PLANNING_DOMAINS)
        if purpose == "report_mapping":
            return set(REPORTING_DOMAINS)
        if role in {"local_deep", "operator_chat"}:
            return {*SAFE_PLANNING_DOMAINS, "mitre_attack"}
        if role == "local_code":
            return {*SAFE_PLANNING_DOMAINS, "binary_exploitation", "kernel_security", "hardware_security"}
        if role == "local_compact":
            return set()
        return set(SAFE_PLANNING_DOMAINS)

    def _restricted_allowed(
        self,
        *,
        role: str,
        task: Task | None,
        purpose: str,
        intent_policy: OperatorIntentPolicy | None,
    ) -> bool:
        if purpose not in {"worker_ai_review", "poc_design", "rag_synthesis"} and role != "local_code":
            return False
        if task is None or task.kind not in POC_TASK_KINDS:
            return False
        if intent_policy is None:
            return False
        if task.kind == TaskKind.POC_APPLICABILITY_VALIDATION:
            return bool(intent_policy.poc_applicability_validation)
        if task.kind == TaskKind.EXPLOIT_RESEARCH:
            return bool(intent_policy.public_poc_research or intent_policy.searchsploit_allowed)
        return bool(
            intent_policy.public_poc_research
            or intent_policy.searchsploit_allowed
            or intent_policy.poc_applicability_validation
            or intent_policy.exploit_code_generation
        )

    def _prompt_sink_reject_reason(self, payload: dict[str, Any], *, purpose: str) -> str:
        try:
            envelope = ContextEnvelope.from_rag_chunk(payload, purpose=purpose, sink="prompt")
        except ValueError as exc:
            return str(exc)
        validation = self.sink_validator.validate("prompt", [envelope], known_rag_refs={envelope.ref})
        if validation.valid:
            return ""
        return "; ".join(validation.errors)

    def _rag_index_reject_reason(self, chunk: DocumentChunk) -> str:
        payload = {
            "chunk_id": chunk.id,
            "citation_id": self._citation_id_for_chunk(chunk),
            "text": chunk.text,
            "metadata": chunk.metadata,
        }
        try:
            envelope = ContextEnvelope.from_rag_chunk(
                payload,
                purpose="rag_retrieval",
                sink="rag_index",
                target_id=chunk.target_id,
            )
        except ValueError as exc:
            return str(exc)
        validation = self.sink_validator.validate("rag_index", [envelope], known_rag_refs={envelope.ref})
        if validation.valid:
            return ""
        return "; ".join(validation.errors)

    def _is_restricted(self, domain: str, metadata: dict[str, Any]) -> bool:
        if domain in RESTRICTED_DOMAINS:
            return True
        if normalized_metadata_value(metadata, "planner_visibility") in {"restricted", "quarantine"}:
            return True
        if normalized_metadata_value(metadata, "risk_level") in {"exploit_validation", "post_exploitation_sensitive"}:
            return True
        return metadata_bool_value(metadata, "requires_operator_approval")

    def _is_taxonomy_only(self, domain: str, planner_visibility: str) -> bool:
        return domain == "mitre_attack" or planner_visibility == "taxonomy_only"

    def _usage_policy_from_metadata(self, metadata: dict[str, Any]) -> str:
        domain = canonical_rag_domain(metadata_value(metadata, "domain") or metadata_value(metadata, "corpus_type"))
        visibility = normalized_metadata_value(metadata, "planner_visibility")
        if self._is_taxonomy_only(domain, visibility):
            return "taxonomy_only"
        if self._is_restricted(domain, metadata):
            return "restricted_gated"
        return "advisory_only"

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


def _is_generated_export_metadata(metadata: dict[str, Any]) -> bool:
    return is_generated_export_metadata(metadata) or is_generated_export_path(metadata_value(metadata, "source_url"))


def _source_refs_metadata_reject_reason(metadata: dict[str, Any]) -> str:
    carrier = SimpleNamespace(metadata=metadata, citations=[])
    if has_malformed_source_refs_metadata(carrier):
        return "malformed source_refs"
    unsupported_refs = unsupported_ai_derived_source_refs(source_refs_metadata_values(carrier))
    if unsupported_refs:
        return f"unsupported source_refs: {', '.join(unsupported_refs)}"
    placeholder_refs = placeholder_source_refs(source_refs_metadata_values(carrier))
    if placeholder_refs:
        return f"placeholder source_refs: {', '.join(placeholder_refs)}"
    uncited_refs = uncited_source_refs_metadata(carrier)
    if uncited_refs:
        return f"uncited source_refs: {', '.join(uncited_refs)}"
    return ""
