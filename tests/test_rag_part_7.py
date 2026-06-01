from __future__ import annotations

from tests.test_rag_common import *


class RagIngestionTestsPart7(RagIngestionTestsBase):
    def test_store_document_chunk_filters_normalize_human_readable_keys(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_store_filter",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-store-filter.jsonl",
                sha256="d" * 64,
                size_bytes=256,
                metadata={"source_type": "methodology_doc"},
            )
        )
        for chunk_index, (chunk_id, corpus_type) in enumerate(
            (
                ("chunk_store_api", "api_security"),
                ("chunk_store_formal", "formal_methods"),
            )
        ):
            self.store.insert_document_chunk(
                DocumentChunk(
                    id=chunk_id,
                    source_artifact_id="artifact_display_store_filter",
                    source_sha256="d" * 64,
                    target_id=self.target.id,
                    chunk_index=chunk_index,
                    title="Display store filter boundary",
                    text="Display store filter boundary text.",
                    token_count=5,
                    metadata={"corpus_type": corpus_type},
                )
            )

        chunks = self.store.list_document_chunks(
            target_id=self.target.id,
            metadata_filters={"Corpus type": ["formal_methods"]},
            limit=10,
        )

        self.assertEqual(self.store.count_document_chunks(metadata_filters={"Corpus type": ["formal_methods"]}), 1)
        self.assertEqual([chunk.id for chunk in chunks], ["chunk_store_formal"])

    def test_store_document_chunk_filters_normalize_human_readable_domain_values(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_store_value_filter",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-store-value-filter.jsonl",
                sha256="e" * 64,
                size_bytes=256,
                metadata={"source_type": "methodology_doc"},
            )
        )
        for chunk_index, (chunk_id, corpus_type) in enumerate(
            (
                ("chunk_store_value_api", "api_security"),
                ("chunk_store_value_writeup", "htb_writeup"),
            )
        ):
            self.store.insert_document_chunk(
                DocumentChunk(
                    id=chunk_id,
                    source_artifact_id="artifact_display_store_value_filter",
                    source_sha256="e" * 64,
                    target_id=self.target.id,
                    chunk_index=chunk_index,
                    title="Display store value filter boundary",
                    text="Display store value filter boundary text.",
                    token_count=6,
                    metadata={"corpus_type": corpus_type},
                )
            )

        chunks = self.store.list_document_chunks(
            target_id=self.target.id,
            metadata_filters={"domain": ["HTB Writeup"]},
            limit=10,
        )

        self.assertEqual(self.store.count_document_chunks(metadata_filters={"domain": ["HTB Writeup"]}), 1)
        self.assertEqual([chunk.id for chunk in chunks], ["chunk_store_value_writeup"])

    def test_role_aware_rag_pack_filters_and_gates_restricted_sources(self) -> None:
        chunks_dir = self._write_preprocessed_chunks(self._role_aware_rag_chunks())
        runtime = PrimordialRuntime(self.config)
        runtime.initialize()
        runtime.rag_import_chunks(chunks_dir)

        fast_pack = runtime.build_rag_context_pack(
            "context anchor authorization exploitation taxonomy",
            purpose="worker_ai_review",
            role="local_fast",
            target=self.target,
            limit=5,
        )
        code_task = Task(
            target_id=self.target.id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.POC_APPLICABILITY_VALIDATION,
            title="PoC applicability review",
            summary="Review restricted source only for gated applicability.",
            role=AgentRole.CODE_WORKER,
            metadata={"allow_ai_review": True},
        )
        runtime.set_operator_intent("htb_lab")
        code_pack = runtime.build_rag_context_pack(
            "context anchor kernel exploitation applicability",
            purpose="worker_ai_review",
            role="local_code",
            task=code_task,
            limit=5,
        )
        action_pack = runtime.build_rag_context_pack(
            "context anchor taxonomy",
            purpose="action_selection",
            role="local_deep",
            target=self.target,
            limit=5,
        )

        self.assertIn("chunk_api_safe", {item["chunk_id"] for item in fast_pack["chunks"]})
        self.assertNotIn("chunk_kernel_restricted", {item["chunk_id"] for item in fast_pack["chunks"]})
        self.assertTrue(any(item["chunk_id"] == "chunk_kernel_restricted" for item in fast_pack["omitted_sources"]))
        self.assertIn("chunk_kernel_restricted", {item["chunk_id"] for item in code_pack["chunks"]})
        self.assertTrue(any(item["chunk_id"] == "chunk_attack_taxonomy" for item in action_pack["omitted_sources"]))
        self.assertTrue(code_pack["prompt_context"])
        runtime.shutdown()

    def _role_aware_rag_chunks(self) -> list[dict[str, object]]:
        return [
            self._rag_chunk(
                "chunk_api_safe",
                "source_api",
                "owasp-api.md",
                "api_security",
                "normal",
                retrieval_text="context anchor BOLA authorization checks object ownership safely.",
            ),
            self._rag_chunk(
                "chunk_kernel_restricted",
                "source_kernel",
                "guide-to-kernel-exploitation.pdf",
                "kernel_security",
                "restricted",
                requires_operator_approval=True,
                retrieval_text="context anchor kernel exploitation source for applicability review only.",
            ),
            self._rag_chunk(
                "chunk_attack_taxonomy",
                "source_attack",
                "mitre-enterprise-attack.json",
                "mitre_attack",
                "taxonomy_only",
                chunk_type="attack_technique",
                retrieval_text="context anchor MITRE ATT&CK taxonomy for reporting and detection mapping.",
            ),
        ]

    def _rag_chunk(
        self,
        chunk_id: str,
        doc_id: str,
        source_file: str,
        domain: str,
        planner_visibility: str,
        *,
        chunk_type: str = "docling_hybrid",
        requires_operator_approval: bool = False,
        retrieval_text: str = "context anchor authorization exploitation taxonomy",
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "chunk_id": chunk_id,
            "doc_id": doc_id,
            "source_file": source_file,
            "source_sha256": "f" * 64,
            "domain": domain,
            "chunk_index": 0,
            "chunk_type": chunk_type,
            "title": "Fixture RAG source",
            "section": "Fixture section",
            "retrieval_text": retrieval_text,
            "raw_text": retrieval_text,
            "requires_authorized_scope": True,
            "risk_level": "exploit_validation" if requires_operator_approval else "safe_planning",
            "planner_visibility": planner_visibility,
        }
        if requires_operator_approval:
            payload["requires_operator_approval"] = True
        return payload

    def test_importer_dry_run_and_duplicate_embedding_skip(self) -> None:
        chunks_dir = self._write_preprocessed_chunks(
            [
                {
                    "chunk_id": "chunk_test_formal_1",
                    "doc_id": "source_formal",
                    "source_file": "decision-procedures.pdf",
                    "source_sha256": "b" * 64,
                    "domain": "formal_methods",
                    "chunk_index": 0,
                    "retrieval_text": "Decision procedures support program verification queries.",
                    "raw_text": "Decision procedures support program verification queries.",
                    "chunk_type": "docling_hybrid",
                    "requires_authorized_scope": True,
                }
            ]
        )
        importer = RagChunkImporter(self.store, DeterministicHashEmbeddingProvider())
        dry_run = importer.import_chunks(RagImportOptions(chunks_dir=chunks_dir, dry_run=True))
        first = importer.import_chunks(RagImportOptions(chunks_dir=chunks_dir))
        second = importer.import_chunks(RagImportOptions(chunks_dir=chunks_dir))
        changed_model = RagChunkImporter(self.store, DeterministicHashEmbeddingProvider(model_name="local-hash-embedding-v2"))
        third = changed_model.import_chunks(RagImportOptions(chunks_dir=chunks_dir))

        self.assertEqual(dry_run.records_seen, 1)
        self.assertEqual(self.store.count_document_chunks(metadata_filters={"domain": "formal_methods"}), 1)
        self.assertEqual(first.embeddings_inserted, 1)
        self.assertEqual(second.embeddings_skipped, 1)
        self.assertEqual(third.embeddings_inserted, 1)

    def test_importer_blocks_policy_blocked_rows(self) -> None:
        chunks_dir = self._write_preprocessed_chunks(
            [
                {
                    "chunk_id": "chunk_blocked",
                    "source_sha256": "c" * 64,
                    "chunk_index": 0,
                    "retrieval_text": "Blocked commercial text.",
                    "policy_blocked": True,
                }
            ]
        )
        importer = RagChunkImporter(self.store, DeterministicHashEmbeddingProvider())
        summary = importer.import_chunks(RagImportOptions(chunks_dir=chunks_dir))

        self.assertEqual(summary.failures, 1)
        self.assertEqual(self.store.count_document_chunks(), 0)

    def test_importer_blocks_human_readable_policy_blocked_rows(self) -> None:
        chunks_dir = self._write_preprocessed_chunks(
            [
                {
                    "Chunk ID": "chunk_display_blocked",
                    "Source SHA256": "d" * 64,
                    "Chunk index": 0,
                    "Retrieval text": "Display-key blocked text must not enter advisory RAG.",
                    "Policy blocked": True,
                }
            ]
        )
        importer = RagChunkImporter(self.store, DeterministicHashEmbeddingProvider())
        summary = importer.import_chunks(RagImportOptions(chunks_dir=chunks_dir))

        self.assertEqual(summary.failures, 1)
        self.assertEqual(self.store.count_document_chunks(), 0)

__all__ = ["RagIngestionTestsPart7"]
