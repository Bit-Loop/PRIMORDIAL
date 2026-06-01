from __future__ import annotations

from primordial.app.runtime_deps import (
    AgentRole,
    json,
    Path,
    Target,
    Task,
)

class RuntimeRagIndexMixin:
    def rag_ingest_document(
        self,
        path: str | Path,
        *,
        target: str,
        use_docling: bool = True,
        embed: bool = True,
        corpus_type: str = "operator_note",
        source_trust: str | None = None,
        hint_policy: str | None = None,
        allow_remote_url: bool = False,
    ) -> dict[str, object]:
        target_record = self._resolve_target_reference(target)
        if target_record is None:
            raise ValueError(f"target not found: {target}")
        return self.rag.ingest_path(
            path,
            target=target_record,
            use_docling=use_docling,
            embed=embed,
            corpus_type=corpus_type,
            source_trust=source_trust,
            hint_policy=hint_policy,
            allow_remote_url=allow_remote_url,
        )

    def rag_search(
        self,
        query: str,
        *,
        target: str | None = None,
        limit: int = 5,
        corpus_types: list[str] | None = None,
        filters: dict[str, object] | None = None,
    ) -> dict[str, object]:
        target_record = self._resolve_target_reference(target) if target else None
        if target and target_record is None:
            raise ValueError(f"target not found: {target}")
        results = self.rag.retrieve(
            query,
            target_id=target_record.id if target_record else None,
            limit=limit,
            corpus_types=corpus_types,
            filters=filters,
        )
        payload_results = [item.as_payload() for item in results]
        return {
            "target": target_record.as_payload() if target_record else None,
            "query": query,
            "corpus_types": corpus_types or [],
            "filters": filters or {},
            "results": payload_results,
            "citation_map": self.rag_context_broker.citation_map_for_chunks(payload_results),
        }

    def build_rag_context_pack(
        self,
        query: str,
        *,
        purpose: str,
        role: str | AgentRole | None = None,
        target: str | Target | None = None,
        task: Task | None = None,
        limit: int = 5,
        filters: dict[str, object] | None = None,
    ) -> dict[str, object]:
        target_record: Target | None
        if isinstance(target, Target):
            target_record = target
        elif target:
            target_record = self._resolve_target_reference(str(target))
            if target_record is None:
                raise ValueError(f"target not found: {target}")
        elif task and task.target_id:
            target_record = self.store.get_target(task.target_id)
        else:
            target_record = None
        pack = self.rag_context_broker.build_pack(
            query,
            purpose=purpose,
            role=role,
            target=target_record,
            task=task,
            limit=limit,
            filters=filters,
            operator_intent=self.active_operator_intent().id,
            intent_policy=self.intent_policy(),
        )
        return pack.as_payload()

    def rag_status(self) -> dict[str, object]:
        counts = self.store.rag_status_counts()
        provider = self.rag_embedding_provider
        return {
            "ok": True,
            "configured_embeddings": {
                "provider": provider.provider_name,
                "model": provider.model_name,
                "dimension": provider.dimension,
                "canonical_model_family": getattr(provider, "canonical_model_family", None),
            },
            "configured_synthesis": {
                "provider": self.config.rag.synthesis.provider,
                "model": self.config.rag.synthesis.model,
                "disallowed_models": list(self.config.rag.synthesis.disallowed_models),
            },
            "last_import": self.store.get_setting(self.RAG_LAST_IMPORT_SETTING, {}),
            **counts,
        }

    def rag_vuln_status(self) -> dict[str, object]:
        payload = self.rag_status()
        payload["vuln_intel_chunks"] = self.store.count_document_chunks(metadata_filters={"domain": ["vuln_intel"]})
        payload["last_vuln_sync"] = self.store.get_setting(self.RAG_LAST_VULN_SYNC_SETTING, {})
        manifest_path = self.config.project_root / "primordial-rag-preprocess" / "output" / "vuln" / "manifests" / "vuln_stream_manifest.json"
        status_path = self.config.project_root / "primordial-rag-preprocess" / "output" / "vuln" / "status" / "vuln_sync_status.json"
        payload["vuln_manifest"] = self._read_optional_json(manifest_path)
        payload["vuln_sync_status_file"] = self._read_optional_json(status_path)
        payload["vuln_chunks_dir"] = str(self.config.project_root / "primordial-rag-preprocess" / "output" / "vuln" / "chunks")
        return payload

    def _read_optional_json(self, path: Path) -> dict[str, object]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (json.JSONDecodeError, OSError) as exc:
            return {"error": str(exc), "path": str(path)}
        return payload if isinstance(payload, dict) else {"value": payload}
