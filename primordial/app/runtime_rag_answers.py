from __future__ import annotations

from primordial.app.runtime_deps import (
    build_rag_synthesis_prompt,
    disallowed_model_response,
    final_rag_synthesis_response,
    metadata_list_value,
    metadata_value,
    prepare_rag_synthesis_context,
    provider_error_response,
    rag_synthesis_system_prompt,
    run_rag_synthesis_provider,
    validate_rag_citations,
    vulnerability_hints_from_results,
)
from primordial.core.sensitive_text import redact_sensitive_text

class RuntimeRagAnswersMixin:
    def rag_eval_probes(
        self,
        queries: list[str],
        *,
        target: str | None = None,
        limit: int = 5,
        corpus_types: list[str] | None = None,
        filters: dict[str, object] | None = None,
    ) -> dict[str, object]:
        clean_queries = [query.strip() for query in queries if str(query).strip()]
        results = []
        for query in clean_queries:
            search = self.rag_search(
                query,
                target=target,
                limit=limit,
                corpus_types=corpus_types,
                filters=filters,
            )
            rows = search.get("results", [])
            top = rows if isinstance(rows, list) else []
            results.append(
                {
                    "query": redact_sensitive_text(query),
                    "result_count": len(top),
                    "top_citations": [self._rag_payload_citation_id(item) for item in top[:5] if isinstance(item, dict)],
                    "top_results": top[:3],
                }
            )
        return {
            "ok": True,
            "mode": "retrieval_only",
            "query_count": len(clean_queries),
            "limit": limit,
            "target": target,
            "corpus_types": corpus_types or [],
            "filters": filters or {},
            "results": results,
        }

    def synthesize_rag_answer(
        self,
        query: str,
        *,
        mode: str = "grounded_answer",
        retrieved_chunks: list[dict[str, object]] | None = None,
        safety_context: dict[str, object] | None = None,
    ) -> dict[str, object]:
        context = prepare_rag_synthesis_context(
            query=query,
            mode=mode,
            retrieved_chunks=retrieved_chunks,
            fallback_search=lambda text: self.rag_search(text, limit=5)["results"],
            citation_map_for_chunks=lambda chunks: self.rag_context_broker.citation_map_for_chunks(chunks),
            citation_id_for_chunk=self._rag_payload_citation_id,
        )
        if context.response:
            return context.response
        model_response = disallowed_model_response(
            synthesis_config=self.config.rag.synthesis,
            chunks=context.chunks,
            citation_map=context.citation_map,
            citation_id_for_chunk=self._rag_payload_citation_id,
            mode=mode,
        )
        if model_response:
            return model_response
        prompt = build_rag_synthesis_prompt(
            query,
            context.chunks,
            mode=mode,
            safety_context=safety_context or {},
            citation_id_for_chunk=self._rag_payload_citation_id,
        )
        try:
            provider_result = run_rag_synthesis_provider(
                synthesis_config=self.config.rag.synthesis,
                ollama=self.ollama,
                system=rag_synthesis_system_prompt(),
                prompt=prompt,
            )
        except Exception as exc:  # noqa: BLE001 - surface model/provider failures as structured runtime output
            return provider_error_response(
                exc=exc,
                chunks=context.chunks,
                citation_map=context.citation_map,
                citation_id_for_chunk=self._rag_payload_citation_id,
            )
        return final_rag_synthesis_response(
            provider_result=provider_result,
            chunks=context.chunks,
            citation_map=context.citation_map,
            mode=mode,
        )

    def rag_cve_search(self, query: str, *, target: str, limit: int = 5) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError(f"target not found: {target}")
        results = self.rag.retrieve(
            query,
            target_id=target_record.id,
            limit=limit,
            corpus_types=["vuln_intel", "cve_advisory", "exploit_note"],
        )
        evidence = self.workflow._current_generation_evidence(target_record, limit=200)
        payload_results: list[dict[str, object]] = []
        for item in results:
            payload = item.as_payload()
            payload["applicability_classification"] = self.workflow._rag_applicability_classification(item.chunk, evidence)
            payload["cve_ids"] = metadata_list_value(item.chunk.metadata, "cve_ids")
            payload["source_trust"] = metadata_value(item.chunk.metadata, "source_trust")
            payload_results.append(payload)
        return {
            "target": target_record.as_payload(),
            "query": redact_sensitive_text(query),
            "corpus_types": ["vuln_intel", "cve_advisory", "exploit_note"],
            "results": payload_results,
        }

    def rag_vuln_search(
        self,
        query: str,
        *,
        limit: int = 8,
        filters: dict[str, object] | None = None,
    ) -> dict[str, object]:
        clean_filters = {"domain": ["vuln_intel"], **(filters or {})}
        return self.rag_search(
            query or "vulnerability remediation detection affected package",
            limit=limit,
            corpus_types=["vuln_intel"],
            filters=clean_filters,
        )

    def rag_vuln_hints(
        self,
        query: str,
        *,
        limit: int = 8,
        filters: dict[str, object] | None = None,
    ) -> dict[str, object]:
        search = self.rag_vuln_search(query, limit=limit, filters=filters)
        hints = vulnerability_hints_from_results(
            [item for item in search.get("results", []) if isinstance(item, dict)]
        )
        return {
            "query": redact_sensitive_text(query),
            "search": search,
            **hints,
        }

    def rag_hints(self, query: str, *, target: str, limit: int = 8) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError(f"target not found: {target}")
        hints = self.workflow.build_rag_task_hints(target_record, query=query, limit=limit)
        return {
            "target": target_record.as_payload(),
            "query": redact_sensitive_text(query),
            "hints": {
                "accepted": hints.get("accepted", []),
                "rejected": hints.get("rejected", []),
            },
            "candidate_actions": [
                {
                    "kind": action.kind.value,
                    "title": action.title,
                    "summary": action.summary,
                    "confidence": action.confidence,
                    "phase": action.phase_label,
                    "subphase": action.subphase,
                    "transition_reason": action.transition_reason,
                    "prerequisite": action.prerequisite,
                    "metadata": dict(action.metadata),
                }
                for action in hints.get("actions", [])
            ],
        }

    def _rag_context_payload(self, question: str, target_id: str | None) -> list[dict[str, object]]:
        pack = self._rag_context_pack_payload(question, target_id)
        chunks = pack.get("chunks", [])
        return [item for item in chunks if isinstance(item, dict)]

    def _rag_context_pack_payload(self, question: str, target_id: str | None) -> dict[str, object]:
        purpose = self._operator_rag_context_purpose(question)
        if not target_id:
            return {
                "query": redact_sensitive_text(question),
                "purpose": purpose,
                "role": "operator_chat",
                "target_id": None,
                "chunks": [],
                "citation_map": [],
                "omitted_sources": [],
                "warnings": [],
                "prompt_context": "",
            }
        try:
            target = self.store.get_target(target_id)
            return self.build_rag_context_pack(
                question,
                purpose=purpose,
                role="operator_chat",
                target=target,
                limit=5,
            )
        except Exception as exc:  # noqa: BLE001 - retrieval must not break operator Q&A
            error = redact_sensitive_text(str(exc))
            return {
                "query": redact_sensitive_text(question),
                "purpose": purpose,
                "role": "operator_chat",
                "target_id": target_id,
                "chunks": [
                    {
                        "error": error,
                        "retrieval_source": "rag_error",
                        "chunk_id": "",
                        "evidence_refs": [],
                    }
                ],
                "citation_map": [],
                "omitted_sources": [],
                "warnings": [error],
                "prompt_context": "",
            }

    def _operator_rag_context_purpose(self, question: str) -> str:
        lowered = question.lower()
        reporting_terms = (
            "mitre",
            "att&ck",
            "attack mapping",
            "map to",
            "mapping",
            "report",
            "detection",
            "mitigation",
            "classify",
            "classification",
            "cwe",
            "owasp",
        )
        return "report_mapping" if any(term in lowered for term in reporting_terms) else "operator_answer"

    def _rag_context_ids(self, rag_context: list[dict[str, object]]) -> list[str]:
        ids: list[str] = []
        for item in rag_context:
            for key in ("citation_id", "chunk_id"):
                ref = str(item.get(key) or "").strip()
                if not ref:
                    continue
                ids.append(ref if ref.startswith("rag:") else f"rag:{ref}")
        return sorted(set(ids))

    def _operator_answer_cites_rag_context(self, body: str, rag_context: list[dict[str, object]]) -> bool:
        clean_context = [item for item in rag_context if not item.get("error")]
        if not self._rag_context_ids(clean_context):
            return True
        return validate_rag_citations(body, clean_context, mode="operator_answer", require_citations=True).valid

    def _deterministic_rag_citation_answer(
        self,
        question: str,
        target_id: str | None,
        rag_context: list[dict[str, object]],
    ) -> str:
        base = self._deterministic_operator_answer(question, target_id)
        lines = []
        for item in rag_context[:5]:
            if item.get("error"):
                continue
            chunk_id = str(item.get("chunk_id") or "")
            citation_id = str(item.get("citation_id") or chunk_id).strip()
            if citation_id and not citation_id.startswith("rag:"):
                citation_id = f"rag:{citation_id}"
            refs = item.get("evidence_refs", [])
            evidence = ", ".join(f"`{ref}`" for ref in refs) if isinstance(refs, list) else ""
            title = str(item.get("source_display") or item.get("title") or "Imported document")
            text = str(item.get("text") or "").replace("\n", " ").strip()
            if len(text) > 220:
                text = text[:220].rstrip() + "..."
            lines.append(f"- `{citation_id}` linked_evidence={evidence or 'none'} advisory_only=true {title}: {text}")
        if not lines:
            return base
        return base + "\n\n**RAG Hints (not evidence)**\n" + "\n".join(lines)
