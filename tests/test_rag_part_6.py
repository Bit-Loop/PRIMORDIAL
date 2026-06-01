from __future__ import annotations

from tests.test_rag_common import *


class RagIngestionTestsPart6(RagIngestionTestsBase):
    def test_operator_answer_citation_gate_counts_curated_citation_without_chunk_id(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        rag_context = [
            {
                "citation_id": "rag:operator-curated-only",
                "text": "Curated-only citation context still requires an explicit citation.",
                "metadata": {
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            }
        ]

        self.assertFalse(runtime._operator_answer_cites_rag_context("Uncited use of RAG.", rag_context))
        self.assertTrue(runtime._operator_answer_cites_rag_context("Cited use of RAG. rag:operator-curated-only", rag_context))
        runtime.shutdown()

    def test_operator_answer_rag_context_withholds_taxonomy_by_default(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        source = self.root / "mitre-mobile.md"
        source.write_text(
            "# MITRE ATT&CK mobile relationship\n\n"
            "FluBot can use Accessibility Services to make removal difficult.\n",
            encoding="utf-8",
        )
        runtime.rag_ingest_document(
            source,
            target=self.target.handle,
            corpus_type="mitre_attack",
            embed=False,
        )

        ordinary = runtime._rag_context_pack_payload("What does FluBot do?", self.target.id)
        mapping = runtime._rag_context_pack_payload("Map FluBot to MITRE detection context", self.target.id)

        self.assertEqual(ordinary["purpose"], "operator_answer")
        self.assertEqual(ordinary["chunks"], [])
        self.assertTrue(any("withheld" in item.get("reason", "") for item in ordinary["omitted_sources"]))
        self.assertEqual(mapping["purpose"], "report_mapping")
        self.assertTrue(mapping["chunks"])
        runtime.shutdown()

    def test_cve_search_classifies_against_current_evidence(self) -> None:
        self.config.manifests_dir = MANIFESTS_DIR
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=self.target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Service discovery",
                summary="OpenSSH service detected on tcp/22.",
                source_ref="fixture://service",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.9,
                freshness=0.9,
                metadata={"kind": "tcp_service_discovery"},
            )
        )
        source = self.root / "openssh-cve.md"
        source.write_text(
            "# OpenSSH CVE\n\n"
            "CVE-2024-6387 is an OpenSSH vulnerability with public PoC notes.\n",
            encoding="utf-8",
        )
        runtime.rag_ingest_document(source, target=self.target.handle, corpus_type="cve_advisory")

        payload = runtime.rag_cve_search("OpenSSH PoC CVE", target=self.target.handle)

        self.assertTrue(payload["results"])
        self.assertEqual(payload["results"][0]["applicability_classification"], "likely")
        runtime.shutdown()

    def test_cve_search_preserves_human_readable_advisory_metadata(self) -> None:
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.store.insert_target(self.target)
        runtime.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_cve",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-cve.jsonl",
                sha256="8" * 64,
                size_bytes=128,
                metadata={"source_type": "vuln_intel_card"},
            )
        )
        runtime.store.insert_document_chunk(
            DocumentChunk(
                id="display_cve_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_cve",
                source_sha256="8" * 64,
                chunk_index=0,
                title="Display CVE metadata",
                text="CVE-2026-0003 describes advisory-only OpenSSH vulnerability context.",
                token_count=9,
                metadata={
                    "corpus_type": "cve_advisory",
                    "CVE IDs": ["CVE-2026-0003"],
                    "Source trust": "official_feed",
                },
            )
        )

        payload = runtime.rag_cve_search("OpenSSH CVE-2026-0003", target=self.target.handle)

        self.assertTrue(payload["results"])
        self.assertEqual(payload["results"][0]["cve_ids"], ["CVE-2026-0003"])
        self.assertEqual(payload["results"][0]["source_trust"], "official_feed")
        runtime.shutdown()

    def test_runtime_imports_preprocessed_chunk_and_search_returns_citation(self) -> None:
        chunks_dir = self._write_preprocessed_chunks(
            [
                {
                    "chunk_id": "chunk_test_api_1",
                    "doc_id": "source_api",
                    "source_file": "owasp-api.md",
                    "source_sha256": "a" * 64,
                    "source_type": "markdown",
                    "domain": "api_web",
                    "corpus_type": ["api_security"],
                    "chunk_index": 0,
                    "chunk_type": "docling_hybrid",
                    "title": "BOLA",
                    "section": "Broken Object Level Authorization",
                    "retrieval_text": "BOLA testing checks object ownership before returning API objects.",
                    "raw_text": "BOLA testing checks object ownership before returning API objects.",
                    "requires_authorized_scope": True,
                    "planner_visibility": "normal",
                    "risk_level": "safe_planning",
                }
            ]
        )
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()

        payload = runtime.rag_import_chunks(chunks_dir, limit=1)
        search = runtime.rag_search("object ownership API", limit=3, filters={"domain": ["api_security"]})

        self.assertEqual(payload["records_seen"], 1)
        self.assertEqual(payload["chunks_inserted"], 1)
        self.assertEqual(payload["embeddings_inserted"], 1)
        self.assertTrue(search["results"])
        self.assertEqual(search["results"][0]["citation_id"], "rag:chunk_test_api_1")
        self.assertEqual(search["citation_map"][0]["source_display"], "Broken Object Level Authorization (owasp-api.md)")
        self.assertEqual(runtime.store.list_targets(), [self.target])
        runtime.shutdown()

    def test_retrieve_honors_human_readable_corpus_type_filter(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_corpus",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-corpus.jsonl",
                sha256="b" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="chunk_display_corpus",
                source_artifact_id="artifact_display_corpus",
                source_sha256="b" * 64,
                target_id=self.target.id,
                chunk_index=0,
                title="Display corpus metadata",
                text="Display corpus metadata should still satisfy API security retrieval.",
                token_count=9,
                metadata={"Corpus type": "api_security"},
            )
        )

        results = self.service.retrieve(
            "display corpus metadata",
            target_id=self.target.id,
            corpus_types=["api_security"],
            use_embeddings=False,
        )

        self.assertEqual([item.chunk.id for item in results], ["chunk_display_corpus"])

    def test_retrieve_normalizes_human_readable_metadata_filter_values(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_filter",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-filter.jsonl",
                sha256="c" * 64,
                size_bytes=256,
                metadata={"source_type": "methodology_doc"},
            )
        )
        for chunk_id, corpus_type in (
            ("chunk_filter_api", "api_security"),
            ("chunk_filter_writeup", "htb_writeup"),
        ):
            self.store.insert_document_chunk(
                DocumentChunk(
                    id=chunk_id,
                    source_artifact_id="artifact_display_filter",
                    source_sha256="c" * 64,
                    target_id=self.target.id,
                    chunk_index=0,
                    title="Display filter boundary",
                    text="Display filter boundary text should be constrained by metadata filters.",
                    token_count=10,
                    metadata={"corpus_type": corpus_type},
                )
            )

        results = self.service.retrieve(
            "display filter boundary",
            target_id=self.target.id,
            filters={"domain": ["HTB Writeup"]},
            use_embeddings=False,
        )

        self.assertEqual([item.chunk.id for item in results], ["chunk_filter_writeup"])

__all__ = ["RagIngestionTestsPart6"]
