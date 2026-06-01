from __future__ import annotations

from tests.test_rag_common import *


class RagIngestionTestsPart9(RagIngestionTestsBase):
    def test_operator_rag_pack_omits_operational_retrieval_disabled_advisory_chunks(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_disabled_advisory",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="disabled-advisory.jsonl",
                sha256="f" * 64,
                size_bytes=0,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="disabled_advisory_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_disabled_advisory",
                source_sha256="f" * 64,
                chunk_index=0,
                title="Retrieval disabled advisory",
                text="Retrieval disabled advisory context must not enter operational RAG prompts.",
                token_count=10,
                metadata={
                    "citation_id": "rag:disabled-advisory",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                    "source_type": "methodology_doc",
                    "operational_retrieval_allowed": False,
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "retrieval disabled advisory context",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:disabled-advisory")
        self.assertEqual(pack.omitted_sources[0]["reason"], "operational_retrieval_disabled")

    def test_operator_rag_pack_omits_unsupported_source_refs_metadata(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_unsupported_source_refs",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="unsupported-source-refs.jsonl",
                sha256="7" * 64,
                size_bytes=0,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="unsupported_source_refs_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_unsupported_source_refs",
                source_sha256="7" * 64,
                chunk_index=0,
                title="Unsupported source refs",
                text="Unsupported provenance refs must not enter operational RAG prompts.",
                token_count=9,
                metadata={
                    "citation_id": "rag:unsupported-source-refs",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                    "source_type": "methodology_doc",
                    "source_refs": ["github:issue-42"],
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "unsupported provenance refs",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:unsupported-source-refs")
        self.assertIn("unsupported source_refs", pack.omitted_sources[0]["reason"])

    def test_operator_rag_pack_omits_uncited_source_refs_metadata(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_uncited_source_refs",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="uncited-source-refs.jsonl",
                sha256="8" * 64,
                size_bytes=0,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="uncited_source_refs_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_uncited_source_refs",
                source_sha256="8" * 64,
                chunk_index=0,
                title="Uncited source refs",
                text="Uncited provenance refs must not enter operational RAG prompts.",
                token_count=9,
                metadata={
                    "citation_id": "rag:uncited-source-refs",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                    "source_type": "methodology_doc",
                    "source_refs": ["rag:curated-source"],
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "uncited provenance refs",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:uncited-source-refs")
        self.assertEqual(pack.omitted_sources[0]["reason"], "uncited source_refs: rag:curated-source")

    def test_operator_rag_pack_omits_legacy_generated_export_source_paths(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_legacy_export_path",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="findings/notion/rag.htb/notion-export.md",
                sha256="1" * 64,
                size_bytes=0,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="legacy_generated_export_path_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_legacy_export_path",
                source_sha256="1" * 64,
                chunk_index=0,
                title="Generated export path",
                text="Generated export path context must not enter operational RAG prompts.",
                token_count=10,
                metadata={
                    "citation_id": "rag:legacy-export-path",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                    "source_type": "methodology_doc",
                    "source_file": "findings/notion/rag.htb/notion-export.md",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "generated export path context",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:legacy-export-path")
        self.assertEqual(pack.omitted_sources[0]["reason"], "generated_export")

    def test_operator_rag_pack_omits_human_readable_generated_export_source_paths(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_export_path",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="advisory/context-source.txt",
                sha256="2" * 64,
                size_bytes=0,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="display_generated_export_path_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_export_path",
                source_sha256="2" * 64,
                chunk_index=0,
                title="Generated export display path",
                text="Display-key generated export path context must not enter operational RAG prompts.",
                token_count=10,
                metadata={
                    "citation_id": "rag:display-export-path",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                    "source_type": "methodology_doc",
                    "Source file": "findings/notion/rag.htb/notion-export.md",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "display generated export path context",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=5,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:display-export-path")
        self.assertEqual(pack.omitted_sources[0]["reason"], "generated_export")

__all__ = ["RagIngestionTestsPart9"]
