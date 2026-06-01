from __future__ import annotations

from tests.test_rag_common import *


class RagIngestionTestsPart3(RagIngestionTestsBase):
    def test_rag_context_pack_blocks_human_readable_taxonomy_metadata_for_actions(self) -> None:
        self.store.insert_artifact(
            ArtifactRecord(
                id="artifact_display_taxonomy",
                task_id=None,
                target_id=self.target.id,
                kind=ArtifactKind.RAG_DOCUMENT,
                path="display-taxonomy.jsonl",
                sha256="4" * 64,
                size_bytes=128,
                metadata={"source_type": "methodology_doc"},
            )
        )
        self.store.insert_document_chunk(
            DocumentChunk(
                id="display_taxonomy_chunk",
                target_id=self.target.id,
                source_artifact_id="artifact_display_taxonomy",
                source_sha256="4" * 64,
                chunk_index=0,
                title="",
                text="Display-key taxonomy context is useful for mapping but cannot drive action selection.",
                token_count=11,
                metadata={
                    "Citation ID": "display-taxonomy-source",
                    "Domain": "mitre_attack",
                    "Planner Visibility": "taxonomy_only",
                },
            )
        )

        pack = RagContextBroker(self.service).build_pack(
            "display key taxonomy action selection",
            purpose="action_selection",
            role="operator_chat",
            target=self.target,
            limit=1,
        )

        self.assertEqual(pack.chunks, [])
        self.assertEqual(pack.omitted_sources[0]["citation_id"], "rag:display-taxonomy-source")
        self.assertIn("taxonomy-only", pack.omitted_sources[0]["reason"])

    def test_rag_citation_map_normalizes_curated_citation_id_prefix(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "preprocessed_chunk_prefix",
                    "citation_id": "curated-source-without-prefix",
                    "title": "Curated prefix source",
                    "metadata": {
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:curated-source-without-prefix")

    def test_rag_citation_map_normalizes_uppercase_rag_citation_prefix(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_uppercase_prefix_chunk",
                    "Citation ID": "RAG:display-uppercase-prefix",
                    "title": "Display uppercase citation prefix source",
                    "metadata": {
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-uppercase-prefix")

    def test_rag_citation_map_uses_top_level_human_readable_citation_id(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_top_level_citation_chunk",
                    "Citation ID": "display-top-level-source",
                    "title": "Display top-level citation source",
                    "metadata": {
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-top-level-source")

    def test_rag_citation_map_preserves_human_readable_source_metadata(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_source_chunk",
                    "text": "Display-key source metadata should survive citation-map rendering.",
                    "metadata": {
                        "Citation ID": "display-source-ref",
                        "Title": "Display source title",
                        "Source file": "curated/display-source.md",
                        "Section": "Display source section",
                        "Page start": 3,
                        "Page end": 4,
                        "Domain": "api_security",
                    },
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-source-ref")
        self.assertEqual(citation_map[0]["source_file"], "curated/display-source.md")
        self.assertEqual(citation_map[0]["source_display"], "Display source section (curated/display-source.md pp. 3-4)")
        self.assertEqual(citation_map[0]["domain"], "api_security")

    def test_rag_citation_map_uses_top_level_human_readable_source_metadata(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_top_level_source_chunk",
                    "text": "Display-key top-level source metadata should survive citation-map rendering.",
                    "Citation ID": "display-top-level-source-metadata",
                    "Title": "Display top-level source title",
                    "Source file": "curated/display-top-level-source.md",
                    "Section": "Display top-level source section",
                    "Page start": 5,
                    "Page end": 6,
                    "Domain": "API Security",
                    "Risk Level": "Exploit Validation",
                    "Planner Visibility": "Taxonomy Only",
                    "metadata": {},
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-top-level-source-metadata")
        self.assertEqual(citation_map[0]["source_file"], "curated/display-top-level-source.md")
        self.assertEqual(
            citation_map[0]["source_display"],
            "Display top-level source section (curated/display-top-level-source.md pp. 5-6)",
        )
        self.assertEqual(citation_map[0]["domain"], "api_security")
        self.assertEqual(citation_map[0]["risk_level"], "exploit_validation")
        self.assertEqual(citation_map[0]["planner_visibility"], "taxonomy_only")
        self.assertEqual(citation_map[0]["usage_policy"], "taxonomy_only")

    def test_rag_citation_map_uses_top_level_human_readable_source_path(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_top_level_source_path_chunk",
                    "Citation ID": "display-top-level-source-path",
                    "Title": "Display top-level source path title",
                    "Source path": "curated/display-top-level-source-path.md",
                    "metadata": {"Domain": "api_security"},
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-top-level-source-path")
        self.assertEqual(citation_map[0]["source_file"], "curated/display-top-level-source-path.md")
        self.assertEqual(
            citation_map[0]["source_display"],
            "Display top-level source path title (curated/display-top-level-source-path.md)",
        )

    def test_rag_citation_map_uses_top_level_human_readable_retrieval_text(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_top_level_retrieval_text_chunk",
                    "Citation ID": "display-top-level-retrieval-text",
                    "Title": "Display top-level retrieval text source",
                    "Retrieval text": "Display-key retrieval text should become the citation excerpt.",
                    "metadata": {"Domain": "api_security"},
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-top-level-retrieval-text")
        self.assertEqual(citation_map[0]["excerpt"], "Display-key retrieval text should become the citation excerpt.")

    def test_rag_citation_map_uses_top_level_human_readable_excerpt(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_top_level_excerpt_chunk",
                    "Citation ID": "display-top-level-excerpt",
                    "Title": "Display top-level excerpt source",
                    "Excerpt": "Display-key excerpt should become the citation excerpt.",
                    "metadata": {"Domain": "api_security"},
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-top-level-excerpt")
        self.assertEqual(citation_map[0]["excerpt"], "Display-key excerpt should become the citation excerpt.")

    def test_rag_citation_map_uses_top_level_human_readable_raw_text(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_top_level_raw_text_chunk",
                    "Citation ID": "display-top-level-raw-text",
                    "Title": "Display top-level raw text source",
                    "Raw text": "Display-key raw text should become the citation excerpt.",
                    "metadata": {"Domain": "api_security"},
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-top-level-raw-text")
        self.assertEqual(citation_map[0]["excerpt"], "Display-key raw text should become the citation excerpt.")

    def test_rag_citation_map_uses_nested_human_readable_excerpt_metadata(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_nested_excerpt_chunk",
                    "Citation ID": "display-nested-excerpt",
                    "Title": "Display nested excerpt source",
                    "metadata": {
                        "Domain": "api_security",
                        "Excerpt": "Nested display-key excerpt should become the citation excerpt.",
                    },
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-nested-excerpt")
        self.assertEqual(citation_map[0]["excerpt"], "Nested display-key excerpt should become the citation excerpt.")

    def test_rag_citation_map_preserves_human_readable_source_display_metadata(self) -> None:
        citation_map = RagContextBroker(self.service).citation_map_for_chunks(
            [
                {
                    "chunk_id": "display_source_display_chunk",
                    "Citation ID": "display-source-display",
                    "metadata": {
                        "Domain": "api_security",
                        "Source display": "Curated display label from source metadata",
                    },
                }
            ]
        )

        self.assertEqual(citation_map[0]["citation_id"], "rag:display-source-display")
        self.assertEqual(citation_map[0]["source_display"], "Curated display label from source metadata")

__all__ = ["RagIngestionTestsPart3"]
