from __future__ import annotations

from tests.test_rag_common import *


class RagIngestionTestsPart10(RagIngestionTestsBase):
    def test_operator_rag_pack_omits_generated_export_source_urls(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_export_source_url",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="remote-generated-export.jsonl",
                sha256="3" * 64,
                size_bytes=0,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="generated_export_source_url_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_export_source_url",
                source_sha256="3" * 64,
                chunk_index=0,
                title="Generated export source URL",
                text="Generated export source URLs must not enter operational RAG prompts.",
                token_count=10,
                metadata={
                    "citation_id": "rag:export-source-url",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                    "source_type": "methodology_doc",
                    "source_url": "https://example.invalid/findings/notion/rag.htb/notion-export.md",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "generated export source URL context",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:export-source-url")
        self.assertEqual(pack.omitted_sources[0]["reason"], "generated_export")

    def test_operator_rag_pack_omits_nested_generated_export_metadata(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_nested_export_marker",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="nested-export-marker.jsonl",
                sha256="4" * 64,
                size_bytes=0,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="nested_generated_export_metadata_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_nested_export_marker",
                source_sha256="4" * 64,
                chunk_index=0,
                title="Nested generated export marker",
                text="Nested generated export metadata must not enter operational RAG prompts.",
                token_count=10,
                metadata={
                    "citation_id": "rag:nested-export-marker",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                    "source_type": "methodology_doc",
                    "metadata": {"origin": "generated_export"},
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "nested generated export metadata",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:nested-export-marker")
        self.assertEqual(pack.omitted_sources[0]["reason"], "generated_export")

    def test_ollama_embedding_provider_can_be_mocked(self) -> None:
        with patch("primordial.core.providers.ollama.OllamaClient.list_models") as list_models, patch(
            "primordial.core.providers.ollama.OllamaClient.embed"
        ) as embed:
            list_models.return_value = OllamaModelListResult(ok=True, models=["nomic-embed-text:v1.5"])
            embed.return_value = OllamaEmbeddingResponse(model="nomic-embed-text:v1.5", embeddings=[[0.1, 0.2]])
            provider = OllamaEmbeddingProvider(model_name="nomic-embed-text:v1.5")

            provider.assert_ready()
            vector = provider.embed("hello")

        self.assertEqual(vector, [0.1, 0.2])
        self.assertEqual(provider.dimension, 2)

    def test_htb_writeup_hint_admits_policy_gated_content_discovery_without_evidence_import(self) -> None:
        self.config.manifests_dir = MANIFESTS_DIR
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        service_evidence = EvidenceRecord(
            target_id=self.target.id,
            type=EvidenceType.TOOL_OUTPUT,
            title="HTTP service evidence",
            summary="HTTP service responds and supports path review.",
            source_ref="fixture://http-service",
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.8,
            freshness=0.9,
            metadata={"kind": "tcp_service_discovery"},
        )
        runtime.store.insert_evidence(service_evidence)
        source = self.root / "writeup.md"
        source.write_text(
            "# HTB hint\n\n"
            "The writeup uses ffuf directory discovery to find hidden endpoints.\n",
            encoding="utf-8",
        )
        ingest = runtime.rag_ingest_document(
            source,
            target=self.target.handle,
            corpus_type="htb_writeup",
            hint_policy="direct_task_hints",
        )

        hints = runtime.rag_hints("directory discovery", target=self.target.handle)

        self.assertIsNone(ingest["evidence"])
        self.assertTrue(hints["candidate_actions"], hints)
        action = hints["candidate_actions"][0]
        self.assertEqual(action["kind"], "web_content_discovery")
        self.assertTrue(action["metadata"]["rag_walkthrough_hint"])
        self.assertEqual(action["metadata"]["supporting_evidence_refs"], [service_evidence.id])
        packet = runtime.workflow._planner_review_packet(
            self.target,
            evidence=[service_evidence],
            surface=runtime.workflow._current_credentialed_access_surface(self.target),
            question="What should happen after HTTP evidence?",
            blockers=[],
            rejected_proposals=[],
            invalid_existing_tasks=[],
            uncertainty_reasons=[],
        )
        self.assertEqual(packet["rag_context"][0]["chunk_id"], ingest["chunks"][0]["id"])
        self.assertTrue(packet["rag_context"][0]["walkthrough_hint"])
        self.assertIn(
            "RAG context is advisory source material; it is not target evidence or approval authority.",
            packet["authority_limits"],
        )
        runtime.shutdown()

    def test_planner_rag_context_preserves_human_readable_direct_hint_metadata(self) -> None:
        self.config.manifests_dir = MANIFESTS_DIR
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        service_evidence = EvidenceRecord(
            target_id=self.target.id,
            type=EvidenceType.TOOL_OUTPUT,
            title="HTTP service evidence",
            summary="HTTP service responds and supports path review.",
            source_ref="fixture://http-service",
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.8,
            freshness=0.9,
            metadata={"kind": "tcp_service_discovery"},
        )
        runtime.store.insert_evidence(service_evidence)
        runtime.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_direct_hint",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-direct-hint.jsonl",
                sha256="7" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        runtime.store.insert_document_chunk(
            DocumentChunk(
                id="display_direct_hint_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_direct_hint",
                source_sha256="7" * 64,
                chunk_index=0,
                title="Display direct hint",
                text="The writeup suggests the next approved web review step after HTTP evidence.",
                token_count=10,
                metadata={
                    "corpus_type": "htb_writeup",
                    "Hint policy": "direct_task_hints",
                    "Primitive hint": "content-discovery",
                    "Source trust": "operator_enabled",
                    "CVE IDs": ["CVE-2026-0002"],
                    "Walkthrough hint": True,
                },
            )
        )

        hints = runtime.rag_hints("HTTP evidence next web review", target=self.target.handle)
        packet = runtime.workflow._planner_review_packet(
            self.target,
            evidence=[service_evidence],
            surface=runtime.workflow._current_credentialed_access_surface(self.target),
            question="What should happen after HTTP evidence?",
            blockers=[],
            rejected_proposals=[],
            invalid_existing_tasks=[],
            uncertainty_reasons=[],
        )

        self.assertTrue(hints["candidate_actions"], hints)
        self.assertEqual(hints["candidate_actions"][0]["kind"], "web_content_discovery")
        self.assertEqual(packet["rag_context"][0]["chunk_id"], "display_direct_hint_chunk")
        self.assertEqual(packet["rag_context"][0]["hint_policy"], "direct_task_hints")
        self.assertEqual(packet["rag_context"][0]["source_trust"], "operator_enabled")
        self.assertEqual(packet["rag_context"][0]["cve_ids"], ["CVE-2026-0002"])
        self.assertTrue(packet["rag_context"][0]["walkthrough_hint"])
        runtime.shutdown()

__all__ = ["RagIngestionTestsPart10"]
