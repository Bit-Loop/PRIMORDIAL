from __future__ import annotations

from tests.test_rag_common import *


class RagIngestionTestsPart8(RagIngestionTestsBase):
    def test_importer_rejects_generated_export_rows(self) -> None:
        chunks_dir = self._write_preprocessed_chunks(
            [
                {
                    "chunk_id": "chunk_export",
                    "doc_id": "source_export",
                    "source_file": "findings/notion/rag.htb/notion-export.md",
                    "source_sha256": "g" * 64,
                    "source_type": "generated_export",
                    "domain": "operator_note",
                    "corpus_type": "operator_note",
                    "chunk_index": 0,
                    "retrieval_text": "Generated Notion export should not become active operational RAG.",
                    "raw_text": "Generated Notion export should not become active operational RAG.",
                    "metadata": {
                        "source_type": "generated_export",
                        "ingest_allowed": False,
                        "operational_retrieval_allowed": False,
                    },
                }
            ]
        )
        importer = RagChunkImporter(self.store, DeterministicHashEmbeddingProvider())
        summary = importer.import_chunks(RagImportOptions(chunks_dir=chunks_dir))

        self.assertEqual(summary.failures, 1)
        self.assertEqual(summary.failed_record_ids, ["chunk_export"])
        self.assertTrue(any("rag_index rejects" in error for error in summary.errors))
        self.assertEqual(self.store.count_document_chunks(), 0)

    def test_corpus_domain_aliases_and_unknown_fallback(self) -> None:
        self.assertEqual(self.service._normalize_corpus_type("api_security"), "api_security")
        self.assertEqual(self.service._normalize_corpus_type("api-web"), "api_security")
        self.assertEqual(self.service._normalize_corpus_type("formal_methods"), "formal_methods")
        self.assertEqual(self.service._normalize_corpus_type("operator_note"), "operator_note")
        self.assertEqual(self.service._normalize_corpus_type("future-domain"), "general_security")

    def test_citation_validator_rejects_invented_and_missing_citations(self) -> None:
        retrieved = [{"chunk_id": "chunk_known", "citation_id": "rag:chunk_known", "metadata": {"domain": "api_security"}}]

        invented = validate_rag_citations("Claim. rag:chunk_other", retrieved)
        missing = validate_rag_citations("Claim without citation.", retrieved)
        valid = validate_rag_citations("Claim with citation. rag:chunk_known", retrieved)

        self.assertFalse(invented.valid)
        self.assertEqual(invented.invented_ids, ["rag:chunk_other"])
        self.assertFalse(missing.valid)
        self.assertTrue(missing.missing_citations)
        self.assertTrue(valid.valid)

    def test_citation_validator_counts_human_readable_metadata_citation_id(self) -> None:
        retrieved = [
            {
                "metadata": {
                    "Citation ID": "display-curated-source",
                    "Domain": "api_security",
                },
            }
        ]

        result = validate_rag_citations("Claim with display-key citation. rag:display-curated-source", retrieved)

        self.assertTrue(result.valid)
        self.assertEqual(result.retrieved_ids, ["rag:display-curated-source"])
        self.assertEqual(result.invented_ids, [])

    def test_mitre_taxonomy_is_blocked_for_action_selection(self) -> None:
        retrieved = [{"chunk_id": "attack_T0001", "metadata": {"domain": "mitre_attack", "planner_visibility": "taxonomy_only"}}]

        result = validate_rag_citations("Use this taxonomy only for reporting. rag:attack_T0001", retrieved, mode="action_selection")

        self.assertFalse(result.valid)
        self.assertEqual(result.blocked_source_use, ["rag:attack_T0001"])

    def test_blocked_source_use_normalizes_curated_citation_id(self) -> None:
        retrieved = [
            {
                "chunk_id": "attack_T0002",
                "citation_id": "curated-attack-source",
                "metadata": {"domain": "mitre_attack", "planner_visibility": "taxonomy_only"},
            }
        ]

        result = validate_rag_citations(
            "Use this taxonomy only for reporting. rag:curated-attack-source",
            retrieved,
            mode="action_selection",
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.blocked_source_use, ["rag:curated-attack-source"])

    def test_blocked_source_use_counts_human_readable_taxonomy_metadata(self) -> None:
        retrieved = [
            {
                "metadata": {
                    "Citation ID": "display-attack-source",
                    "Domain": "mitre_attack",
                    "Planner Visibility": "taxonomy_only",
                },
            }
        ]

        result = validate_rag_citations(
            "Use this taxonomy only for reporting. rag:display-attack-source",
            retrieved,
            mode="action_selection",
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.blocked_source_use, ["rag:display-attack-source"])

    def test_rag_synthesis_rejects_qwen_model(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.config.rag.synthesis.model = "qwen3-coder-next:q4_K_M"
        result = runtime.synthesize_rag_answer(
            "What is BOLA?",
            retrieved_chunks=[
                {
                    "chunk_id": "chunk_api",
                    "citation_id": "rag:chunk_api",
                    "text": "BOLA means Broken Object Level Authorization.",
                    "metadata": {"domain": "api_security"},
                }
            ],
        )

        self.assertEqual(result["status"], "disallowed_model")
        self.assertEqual(disallowed_rag_synthesis_model("qwen3-coder-next:q4_K_M", ("qwen",)), "qwen")
        runtime.shutdown()

    def test_operational_rag_synthesis_rejects_supplied_generated_export_chunks(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.config.rag.synthesis.model = "allowed-model"
        result = runtime.synthesize_rag_answer(
            "What should the planner do next?",
            mode="planner",
            retrieved_chunks=[
                {
                    "chunk_id": "generated-export",
                    "citation_id": "rag:generated-export",
                    "text": "Generated export prose must not be synthesized into operational guidance.",
                    "metadata": {
                        "source_type": "generated_export",
                        "origin": "generated_export",
                        "ingest_allowed": False,
                        "operational_retrieval_allowed": False,
                    },
                }
            ],
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "invalid_rag_context")
        self.assertIn("generated_export", result["error"])
        runtime.shutdown()

    def test_operational_rag_synthesis_accepts_supplied_markdown_advisory_chunks(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.config.rag.synthesis.model = "qwen3-coder-next:q4_K_M"
        result = runtime.synthesize_rag_answer(
            "What should the planner do next?",
            mode="planner",
            retrieved_chunks=[
                {
                    "chunk_id": "methodology",
                    "citation_id": "rag:methodology",
                    "text": "Advisory methodology context should survive validation.",
                    "metadata": {
                        "source_type": "markdown",
                        "domain": "api_security",
                        "corpus_type": "api_security",
                    },
                }
            ],
        )

        self.assertEqual(result["status"], "disallowed_model")
        self.assertEqual(result["retrieved_ids"], ["rag:methodology"])
        runtime.shutdown()

    def test_rag_synthesis_disallowed_model_normalizes_curated_retrieved_ids(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.config.rag.synthesis.model = "qwen3-coder-next:q4_K_M"
        result = runtime.synthesize_rag_answer(
            "What should the planner do next?",
            mode="planner",
            retrieved_chunks=[
                {
                    "chunk_id": "methodology_diag",
                    "citation_id": "methodology-curated-diag",
                    "text": "Advisory methodology context should retain its curated citation.",
                    "metadata": {
                        "source_type": "markdown",
                        "domain": "api_security",
                        "corpus_type": "api_security",
                    },
                }
            ],
        )

        self.assertEqual(result["status"], "disallowed_model")
        self.assertEqual(result["retrieved_ids"], ["rag:methodology-curated-diag"])
        runtime.shutdown()

    def test_operator_rag_pack_omits_legacy_generated_export_chunks(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        runtime.store.insert_artifact(
            ArtifactRecord(
                id="artifact_legacy_generated_export",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.EXPORT,
                path="findings/notion/rag.htb/generated-export.md",
                sha256="e" * 64,
                size_bytes=0,
                metadata={"origin": "generated_export", "ingest_allowed": False},
            )
        )
        runtime.store.insert_document_chunk(
            DocumentChunk(
                id="legacy_generated_export_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_legacy_generated_export",
                source_sha256="e" * 64,
                chunk_index=0,
                title="Generated export",
                text="Generated export operator strategy must not enter operational prompts.",
                token_count=9,
                metadata={
                    "corpus_type": "operator_note",
                    "domain": "operator_note",
                    "source_type": "generated_export",
                    "origin": "generated_export",
                    "operational_retrieval_allowed": False,
                },
            )
        )

        pack = runtime.build_rag_context_pack(
            "generated export operator strategy",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack["chunks"], [])
        self.assertTrue(any(item["chunk_id"] == "legacy_generated_export_chunk" for item in pack["omitted_sources"]))
        self.assertTrue(any("generated_export" in item["reason"] for item in pack["omitted_sources"]))
        runtime.shutdown()

__all__ = ["RagIngestionTestsPart8"]
