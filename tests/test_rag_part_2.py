from __future__ import annotations

from tests.test_rag_common import *


class RagIngestionTestsPart2(RagIngestionTestsBase):
    def test_rag_context_pack_normalizes_uppercase_rag_citation_prefix(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_uppercase_preprocessed",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="uppercase-preprocessed.jsonl",
                sha256="6" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="uppercase_preprocessed_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_uppercase_preprocessed",
                source_sha256="6" * 64,
                chunk_index=0,
                title="Uppercase curated source",
                text="Retrieved RAG pack citations should use canonical lowercase prefixes.",
                token_count=9,
                metadata={
                    "citation_id": "RAG:uppercase-curated-source",
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "uppercase curated source",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=1,
        )

        self.assertEqual(pack.chunks[0]["citation_id"], "rag:uppercase-curated-source")
        self.assertEqual(pack.citation_map[0]["citation_id"], "rag:uppercase-curated-source")
        self.assertIn("[rag:uppercase-curated-source]", pack.prompt_context())

    def test_rag_context_pack_preserves_human_readable_source_metadata(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_preprocessed",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-preprocessed.jsonl",
                sha256="3" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="display_preprocessed_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_preprocessed",
                source_sha256="3" * 64,
                chunk_index=0,
                title="",
                text="Display-key source metadata should survive retrieved RAG pack rendering.",
                token_count=9,
                metadata={
                    "Citation ID": "display-pack-source",
                    "Title": "Display pack title",
                    "Source file": "curated/display-pack.md",
                    "Section": "Display pack section",
                    "Page start": 7,
                    "Page end": 8,
                    "Domain": "api_security",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "display key source metadata rendering",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=1,
        )

        self.assertEqual(pack.citation_map[0]["citation_id"], "rag:display-pack-source")
        self.assertEqual(pack.citation_map[0]["source_file"], "curated/display-pack.md")
        self.assertEqual(pack.citation_map[0]["source_display"], "Display pack section (curated/display-pack.md pp. 7-8)")
        self.assertIn("[rag:display-pack-source]", pack.prompt_context())

    def test_rag_context_pack_preserves_human_readable_source_display_metadata(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_source_label",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-source-label.jsonl",
                sha256="8" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="display_source_label_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_source_label",
                source_sha256="8" * 64,
                chunk_index=0,
                title="",
                text="Display-key source labels should survive retrieved RAG pack rendering.",
                token_count=9,
                metadata={
                    "Citation ID": "display-pack-source-label",
                    "Domain": "api_security",
                    "Source display": "Curated display label from stored source metadata",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "display key source label rendering",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=1,
        )

        self.assertEqual(pack.citation_map[0]["citation_id"], "rag:display-pack-source-label")
        self.assertEqual(pack.citation_map[0]["source_display"], "Curated display label from stored source metadata")
        self.assertIn("[rag:display-pack-source-label] Curated display label from stored source metadata", pack.prompt_context())

    def test_rag_context_pack_prompt_labels_human_readable_domain(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_domain",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-domain.jsonl",
                sha256="5" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="display_domain_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_domain",
                source_sha256="5" * 64,
                chunk_index=0,
                title="Display domain label",
                text="Display-key domain metadata should remain visible in prompt labels.",
                token_count=9,
                metadata={
                    "Citation ID": "display-domain-source",
                    "Domain": "api_security",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "display key domain prompt label",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=1,
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:display-domain-source]", rendered)
        self.assertIn("domain=api_security", rendered)
        self.assertEqual(pack.chunks[0]["metadata"]["domain"], "api_security")

    def test_rag_context_pack_preserves_human_readable_hint_metadata(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_hint_metadata",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-hint-metadata.jsonl",
                sha256="6" * 64,
                size_bytes=128,
                metadata={"source_type": "vuln_intel_card"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="display_hint_metadata_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_hint_metadata",
                source_sha256="6" * 64,
                chunk_index=0,
                title="Display hint metadata",
                text="Display-key advisory hint metadata should remain machine-readable.",
                token_count=9,
                metadata={
                    "Citation ID": "display-hint-metadata-source",
                    "Domain": "cve_advisory",
                    "Source trust": "official_feed",
                    "Hint policy": "advisory",
                    "CVE IDs": ["CVE-2026-0001"],
                    "Walkthrough hint": True,
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "display key advisory hint metadata",
            purpose="operator_answer",
            role="operator_chat",
            target=self.target,
            limit=1,
        )
        chunk = pack.chunks[0]

        self.assertEqual(chunk["source_trust"], "official_feed")
        self.assertEqual(chunk["hint_policy"], "advisory")
        self.assertEqual(chunk["cve_ids"], ["CVE-2026-0001"])
        self.assertTrue(chunk["walkthrough_hint"])
        self.assertEqual(chunk["metadata"]["source_trust"], "official_feed")
        self.assertEqual(chunk["metadata"]["hint_policy"], "advisory")

__all__ = ["RagIngestionTestsPart2"]
