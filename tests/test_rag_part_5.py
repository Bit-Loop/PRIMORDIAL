from __future__ import annotations

from tests.test_rag_common import *


class RagIngestionTestsPart5(RagIngestionTestsBase):
    def test_rag_context_prompt_uses_human_readable_top_level_source_display(self) -> None:
        pack = RagContextPack(
            query="display source prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_source_chunk",
                    "Citation ID": "display-source-top-level",
                    "Source display": "Top-level display source label",
                    "Retrieval text": "Top-level display retrieval text should render.",
                    "metadata": {"Domain": "api_security"},
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:display-source-top-level] Top-level display source label", rendered)
        self.assertIn("Top-level display retrieval text should render.", rendered)
        self.assertNotIn("[rag:display_source_chunk]", rendered)

    def test_rag_chunk_inspect_resolves_curated_citation_id(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        runtime.store.insert_artifact(
            ArtifactRecord(
                id="artifact_inspect_curated",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="inspect-curated-source.jsonl",
                sha256="c" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        runtime.store.insert_document_chunk(
            DocumentChunk(
                id="preprocessed_chunk_inspect",
                target_id=self.target.id,
                source_artifact_id="artifact_inspect_curated",
                source_sha256="c" * 64,
                chunk_index=0,
                title="Inspectable curated source",
                text="Chunk inspection should resolve curated citation identifiers.",
                token_count=8,
                metadata={
                    "citation_id": "rag:inspect-curated-source",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            )
        )

        inspected = runtime.rag_chunk_inspect("rag:inspect-curated-source")

        self.assertEqual(inspected["chunk"]["id"], "preprocessed_chunk_inspect")
        self.assertEqual(inspected["chunk"]["citation_id"], "rag:inspect-curated-source")
        runtime.shutdown()

    def test_rag_source_profile_preserves_curated_sample_citation_id(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        runtime.store.insert_artifact(
            ArtifactRecord(
                id="artifact_profile_curated",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="profile-curated-source.jsonl",
                sha256="d" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        runtime.store.insert_document_chunk(
            DocumentChunk(
                id="preprocessed_chunk_profile",
                target_id=self.target.id,
                source_artifact_id="artifact_profile_curated",
                source_sha256="d" * 64,
                chunk_index=0,
                title="Profiled curated source",
                text="Source profile sample chunks should preserve curated citation identifiers.",
                token_count=9,
                metadata={
                    "doc_id": "curated_doc",
                    "citation_id": "rag:profile-curated-source",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            )
        )

        profile = runtime.rag_source_profile("curated_doc", limit=1)

        self.assertEqual(profile["sample_chunks"][0]["chunk_id"], "preprocessed_chunk_profile")
        self.assertEqual(profile["sample_chunks"][0]["citation_id"], "rag:profile-curated-source")
        runtime.shutdown()

    def test_rag_eval_probes_normalizes_curated_top_citations(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()

        def fake_rag_search(
            query: str,
            *,
            target: str | None = None,
            limit: int = 5,
            corpus_types: list[str] | None = None,
            filters: dict[str, object] | None = None,
        ) -> dict[str, object]:
            return {
                "query": query,
                "target": target,
                "corpus_types": corpus_types or [],
                "filters": filters or {},
                "results": [
                    {
                        "chunk_id": "eval_chunk",
                        "citation_id": "eval-curated-source",
                        "text": "Curated advisory context for retrieval evaluation.",
                        "metadata": {"domain": "api_security"},
                    }
                ],
                "citation_map": [],
            }

        runtime.rag_search = fake_rag_search  # type: ignore[method-assign]
        payload = runtime.rag_eval_probes(["retrieval evaluation"], limit=1)

        self.assertEqual(payload["results"][0]["top_citations"], ["rag:eval-curated-source"])
        runtime.shutdown()

    def test_generated_notion_exports_are_not_ingested_as_active_rag(self) -> None:
        export_dir = self.root / "findings" / "notion" / self.target.handle
        export_dir.mkdir(parents=True)
        source = export_dir / "notion-export.md"
        source.write_text(
            "# RAG Target Notion Export\n\n"
            "## Evidence References\n\n"
            "- `evidence:current` Sparse real evidence.\n\n"
            "## AI Summaries\n\n"
            "- Generated strategy text must not become active RAG.\n",
            encoding="utf-8",
        )

        with self.assertRaises(DocumentIngestionError) as raised:
            self.service.ingest_path(source, target=self.target, corpus_type="operator_note")

        self.assertIn("generated export", str(raised.exception))
        self.assertEqual(self.store.count_document_chunks(), 0)
        self.assertEqual(self.store.list_evidence(target_id=self.target.id, limit=20), [])

    def test_generic_generated_exports_are_not_ingested_as_active_rag(self) -> None:
        source = self.root / "generated-export.md"
        source.write_text(
            "# Generated Export\n\n"
            "Generated context exports must not recurse into active RAG ingestion.\n",
            encoding="utf-8",
        )

        with self.assertRaises(DocumentIngestionError) as raised:
            self.service.ingest_path(source, target=self.target, corpus_type="operator_note")

        self.assertIn("generated export", str(raised.exception))
        self.assertEqual(self.store.count_document_chunks(), 0)
        self.assertEqual(self.store.list_evidence(target_id=self.target.id, limit=20), [])

    def test_findings_notion_exports_are_not_ingested_by_absolute_path(self) -> None:
        export_dir = self.root / "findings" / "notion" / self.target.handle
        export_dir.mkdir(parents=True)
        source = export_dir / "current-summary.md"
        source.write_text(
            "# Current Summary\n\n"
            "Any findings/notion markdown export must not recurse into active RAG ingestion.\n",
            encoding="utf-8",
        )

        with self.assertRaises(DocumentIngestionError) as raised:
            self.service.ingest_path(source, target=self.target, corpus_type="operator_note")

        self.assertIn("generated export", str(raised.exception))
        self.assertEqual(self.store.count_document_chunks(), 0)
        self.assertEqual(self.store.list_evidence(target_id=self.target.id, limit=20), [])

    def test_runtime_operator_prompt_includes_cited_rag_context(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.config.ensure_directories()
        runtime.credentials.initialize()
        runtime.skills.initialize()
        runtime.findings_context.initialize()
        runtime.store.initialize()
        runtime.store.insert_target(self.target)
        source = self.root / "findings.md"
        source.write_text(
            "# Imported Finding\n\n"
            "A markdown document says the target has a document upload parser worth reviewing.\n",
            encoding="utf-8",
        )
        ingest = runtime.rag_ingest_document(source, target=self.target.handle)

        prompt = runtime._build_operator_prompt("What document upload evidence exists?", self.target.id)
        rag_context = runtime._rag_context_payload("What document upload evidence exists?", self.target.id)
        fallback = runtime._deterministic_rag_citation_answer(
            "What document upload evidence exists?",
            self.target.id,
            rag_context,
        )

        self.assertIn('"rag_context"', prompt)
        self.assertIn(ingest["chunks"][0]["id"], prompt)
        self.assertIn(ingest["evidence"]["id"], prompt)
        self.assertFalse(runtime._operator_answer_cites_rag_context("The document says uploads matter.", rag_context))
        self.assertTrue(runtime._operator_answer_cites_rag_context(f"rag:{ingest['chunks'][0]['id']}", rag_context))
        self.assertIn("**RAG Hints (not evidence)**", fallback)
        self.assertIn(f"rag:{ingest['chunks'][0]['id']}", fallback)

    def test_deterministic_operator_rag_fallback_preserves_curated_citation_id(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)

        fallback = runtime._deterministic_rag_citation_answer(
            "What source guidance applies?",
            self.target.id,
            [
                {
                    "chunk_id": "preprocessed_operator_context",
                    "citation_id": "rag:operator-curated-source",
                    "source_display": "Curated operator source",
                    "text": "Curated source identities must survive deterministic fallback answers.",
                    "evidence_refs": [],
                    "metadata": {
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                }
            ],
        )

        self.assertIn("`rag:operator-curated-source`", fallback)
        self.assertNotIn("`rag:preprocessed_operator_context`", fallback)
        runtime.shutdown()

__all__ = ["RagIngestionTestsPart5"]
