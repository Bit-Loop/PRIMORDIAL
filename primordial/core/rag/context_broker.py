from __future__ import annotations

from typing import Any

from primordial.core.context.normalization import (
    canonical_rag_domain,
    metadata_bool_value,
    metadata_list_value,
    metadata_value,
    normalized_metadata_value,
)
from primordial.core.context.sinks import ContextSinkValidator
from primordial.core.domain.enums import AgentRole
from primordial.core.domain.models import Target, Task
from primordial.core.intent.models import OperatorIntentPolicy
from primordial.core.rag.context_models import RagContextPack
from primordial.core.rag.context_policy import RagContextPolicyMixin
from primordial.core.rag.context_sources import RagContextSourceMixin
from primordial.core.rag.documents import DocumentIngestionService, RagContextItem


class RagContextBroker(RagContextPolicyMixin, RagContextSourceMixin):
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
        pack = RagContextPack(query=clean_query, purpose=clean_purpose, role=clean_role, target_id=target.id if target else None)
        if not clean_query:
            pack.warnings.append("empty query; no RAG context retrieved")
            return pack
        raw_items = self._retrieve(clean_query, target_id=target.id if target else None, limit=max(limit * 4, limit), filters=filters)
        seen: set[str] = set()
        for item in raw_items:
            if item.chunk.id in seen:
                continue
            seen.add(item.chunk.id)
            if self._append_item_to_pack(
                pack,
                item,
                purpose=clean_purpose,
                role=clean_role,
                task=task,
                operator_intent=operator_intent,
                intent_policy=intent_policy,
            ) and len(pack.chunks) >= limit:
                break
        self._add_pack_warnings(pack)
        return pack

    def citation_map_for_chunks(self, chunks: list[dict[str, Any]]) -> list[dict[str, object]]:
        sources: list[dict[str, object]] = []
        for item in chunks:
            source = self._source_from_payload(item)
            if source is not None:
                sources.append(source.as_payload())
        return sources

    def _append_item_to_pack(
        self,
        pack: RagContextPack,
        item: RagContextItem,
        *,
        purpose: str,
        role: str,
        task: Task | None,
        operator_intent: str | None,
        intent_policy: OperatorIntentPolicy | None,
    ) -> bool:
        source = self._source_for_item(item)
        reason = self._reject_reason(
            item.chunk,
            purpose=purpose,
            role=role,
            task=task,
            operator_intent=operator_intent,
            intent_policy=intent_policy,
        )
        if reason:
            omitted = source.as_payload()
            omitted["reason"] = reason
            pack.omitted_sources.append(omitted)
            return False
        payload = self._payload_for_context_item(item, source)
        prompt_reject_reason = self._prompt_sink_reject_reason(payload, purpose=purpose)
        if prompt_reject_reason:
            omitted = source.as_payload()
            omitted["reason"] = prompt_reject_reason
            pack.omitted_sources.append(omitted)
            return False
        pack.chunks.append(payload)
        pack.citation_map.append(source.as_payload())
        return True

    def _payload_for_context_item(self, item: RagContextItem, source: object) -> dict[str, Any]:
        payload = item.as_payload(max_chars=1100)
        payload["citation_id"] = source.citation_id
        payload["source_display"] = source.source_display
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        corpus_type = canonical_rag_domain(metadata_value(metadata, "corpus_type") or source.domain)
        payload["metadata"] = self._payload_metadata(metadata, source=source, corpus_type=corpus_type)
        payload["corpus_type"] = corpus_type
        payload["source_trust"] = normalized_metadata_value(metadata, "source_trust")
        payload["hint_policy"] = normalized_metadata_value(metadata, "hint_policy")
        payload["cve_ids"] = list(metadata_list_value(metadata, "cve_ids"))
        payload["walkthrough_hint"] = metadata_bool_value(metadata, "walkthrough_hint") or corpus_type == "htb_writeup"
        return payload

    def _payload_metadata(self, metadata: dict[str, Any], *, source: object, corpus_type: str) -> dict[str, Any]:
        return {
            **metadata,
            "domain": source.domain,
            "corpus_type": corpus_type,
            "source_display": source.source_display,
            "usage_policy": source.usage_policy,
            "source_trust": normalized_metadata_value(metadata, "source_trust"),
            "hint_policy": normalized_metadata_value(metadata, "hint_policy"),
            "cve_ids": list(metadata_list_value(metadata, "cve_ids")),
            "walkthrough_hint": metadata_bool_value(metadata, "walkthrough_hint"),
        }

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
