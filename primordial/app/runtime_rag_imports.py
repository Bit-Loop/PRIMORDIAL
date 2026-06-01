from __future__ import annotations

from primordial.app.runtime_deps import (
    Path,
    RagChunkImporter,
    RagImportOptions,
    utc_now,
    VulnFeedSyncer,
    VulnSyncOptions,
)

class RuntimeRagImportsMixin:
    def rag_vuln_sync(
        self,
        *,
        since_year: int = 2020,
        embed_all: bool = True,
        sources: list[str] | None = None,
        timeout_seconds: float = 45.0,
        rate_limit_seconds: float | None = None,
        max_nvd_pages: int | None = None,
        max_enrichment_cves: int = 250,
        skip_import: bool = False,
        force: bool = False,
        reembed: bool = False,
        skip_embeddings: bool = False,
        limit: int | None = None,
    ) -> dict[str, object]:
        allowed_sources = {"nvd", "kev", "epss", "cvelist_v5", "osv", "ghsa"}
        selected_sources = {str(source).strip() for source in sources or [] if str(source).strip()}
        if not selected_sources:
            selected_sources = set(allowed_sources)
        unknown = sorted(selected_sources - allowed_sources)
        if unknown:
            raise ValueError(f"unsupported vuln sync source(s): {', '.join(unknown)}")
        options = VulnSyncOptions(
            since_year=max(1999, int(since_year)),
            embed_all=bool(embed_all),
            sources=selected_sources,
            timeout_seconds=max(1.0, float(timeout_seconds)),
            rate_limit_seconds=rate_limit_seconds,
            max_nvd_pages=max_nvd_pages,
            max_enrichment_cves=max(0, int(max_enrichment_cves)),
        )
        syncer = VulnFeedSyncer(self.config.project_root)
        sync = syncer.sync(options)
        chunks_dir = Path(sync.get("chunks_dir") or self.config.project_root / "primordial-rag-preprocess" / "output" / "vuln" / "chunks")
        import_summary = None
        if not skip_import:
            import_summary = self.rag_import_chunks(
                chunks_dir,
                force=force,
                reembed=reembed,
                skip_embeddings=skip_embeddings,
                domains=["vuln_intel"],
                limit=limit,
            )
        result: dict[str, object] = {
            "ok": True,
            "sync": sync,
            "import": import_summary,
            "vuln_intel_chunks": self.store.count_document_chunks(metadata_filters={"domain": ["vuln_intel"]}),
            "chunks_dir": str(chunks_dir),
            "hints_only": True,
        }
        self.store.set_setting(
            self.RAG_LAST_VULN_SYNC_SETTING,
            {
                "completed_at": utc_now().isoformat(),
                "since_year": options.since_year,
                "embed_all": options.embed_all,
                "sources": sorted(selected_sources),
                "source_failures": sync.get("source_failures", {}),
                "preprocess_manifest": sync.get("preprocess_manifest", {}),
                "import": import_summary,
                "vuln_intel_chunks": result["vuln_intel_chunks"],
                "chunks_dir": str(chunks_dir),
            },
        )
        return result

    def rag_config_payload(self) -> dict[str, object]:
        return {
            "ok": True,
            "embeddings": {
                "provider": self.config.rag.embeddings.provider,
                "base_url": self.config.rag.embeddings.base_url,
                "model": self.config.rag.embeddings.model,
                "batch_size": self.config.rag.embeddings.batch_size,
                "timeout_seconds": self.config.rag.embeddings.timeout_seconds,
                "canonical_model_family": self.config.rag.embeddings.canonical_model_family,
            },
            "synthesis": {
                "provider": self.config.rag.synthesis.provider,
                "base_url": self.config.rag.synthesis.base_url,
                "model": self.config.rag.synthesis.model,
                "temperature": self.config.rag.synthesis.temperature,
                "max_tokens": self.config.rag.synthesis.max_tokens,
                "backup_allowed_models": list(self.config.rag.synthesis.backup_allowed_models),
                "disallowed_models": list(self.config.rag.synthesis.disallowed_models),
            },
            "default_chunks_dir": str(self.config.project_root / "primordial-rag-preprocess" / "output" / "chunks"),
            "supported_domains": sorted(self.rag.CORPUS_TYPES),
            "context_pack_purposes": [
                "operator_answer",
                "planner_review",
                "worker_ai_review",
                "rag_synthesis",
                "report_mapping",
                "poc_design",
            ],
            "context_pack_roles": ["local_fast", "local_deep", "local_code", "local_compact", "operator_chat"],
            "supported_filters": [
                "domain",
                "source_file",
                "doc_id",
                "chunk_type",
                "card_type",
                "risk_family",
                "output_mode",
                "source_priority",
                "requires_authorized_scope",
                "vuln_id",
                "cve_id",
                "ghsa_id",
                "osv_id",
                "alias",
                "ecosystem",
                "package",
                "vendor",
                "product",
                "cpe",
                "purl",
                "cwe",
                "cvss_severity",
                "kev",
                "epss_probability",
                "epss_percentile",
                "fixed_version_known",
                "asset_match",
                "watchlist_match",
                "source_kind",
                "safety_level",
            ],
            "allowed_use_modes": [
                "authorized_bug_bounty",
                "ctf",
                "local_lab",
                "defensive_assessment",
                "academic_study",
            ],
        }

    def rag_import_chunks(
        self,
        chunks_dir: str | Path | None = None,
        *,
        dry_run: bool = False,
        force: bool = False,
        reembed: bool = False,
        skip_embeddings: bool = False,
        domains: list[str] | None = None,
        source_files: list[str] | None = None,
        doc_ids: list[str] | None = None,
        limit: int | None = None,
    ) -> dict[str, object]:
        importer = RagChunkImporter(
            self.store,
            self.rag_embedding_provider,
            batch_size=self.config.rag.embeddings.batch_size,
        )
        options = RagImportOptions(
            chunks_dir=Path(chunks_dir or self.config.project_root / "primordial-rag-preprocess" / "output" / "chunks"),
            dry_run=dry_run,
            force=force,
            reembed=reembed,
            skip_embeddings=skip_embeddings,
            domains={str(item).strip() for item in domains or [] if str(item).strip()},
            source_files={str(item).strip() for item in source_files or [] if str(item).strip()},
            doc_ids={str(item).strip() for item in doc_ids or [] if str(item).strip()},
            limit=limit,
        )
        summary = importer.import_chunks(options).as_payload()
        self._record_rag_import_summary(summary, options=options)
        return summary

    def _record_rag_import_summary(self, summary: dict[str, object], *, options: RagImportOptions) -> None:
        compact = {
            "completed_at": utc_now().isoformat(),
            "chunks_dir": str(options.chunks_dir),
            "dry_run": options.dry_run,
            "force": options.force,
            "reembed": options.reembed,
            "skip_embeddings": options.skip_embeddings,
            "domains": sorted(options.domains),
            "source_files": sorted(options.source_files),
            "doc_ids": sorted(options.doc_ids),
            "limit": options.limit,
            "files_seen": summary.get("files_seen", 0),
            "records_seen": summary.get("records_seen", 0),
            "chunks_inserted": summary.get("chunks_inserted", 0),
            "chunks_updated": summary.get("chunks_updated", 0),
            "chunks_skipped": summary.get("chunks_skipped", 0),
            "embeddings_inserted": summary.get("embeddings_inserted", 0),
            "embeddings_updated": summary.get("embeddings_updated", 0),
            "embeddings_skipped": summary.get("embeddings_skipped", 0),
            "failures": summary.get("failures", 0),
            "embedding_provider": summary.get("embedding_provider"),
            "embedding_model": summary.get("embedding_model"),
            "failed_record_ids": list(summary.get("failed_record_ids", []) if isinstance(summary.get("failed_record_ids"), list) else [])[:100],
            "errors": list(summary.get("errors", []) if isinstance(summary.get("errors"), list) else [])[:20],
        }
        self.store.set_setting(self.RAG_LAST_IMPORT_SETTING, compact)
