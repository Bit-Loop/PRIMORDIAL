from __future__ import annotations

from tests.test_rag_common import *


class RagIngestionTestsPart4(RagIngestionTestsBase):
    def test_rag_context_prompt_normalizes_curated_citation_ids(self) -> None:
        pack = RagContextPack(
            query="curated prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "prompt_chunk",
                    "citation_id": "curated-prompt-source",
                    "title": "Curated prompt source",
                    "text": "Curated source context should render with canonical RAG citations.",
                    "metadata": {"domain": "api_security"},
                }
            ],
            omitted_sources=[{"citation_id": "omitted-curated-source", "reason": "role_forbidden"}],
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:curated-prompt-source]", rendered)
        self.assertIn("rag:omitted-curated-source:role_forbidden", rendered)
        self.assertNotIn("[curated-prompt-source]", rendered)
        self.assertNotIn(" omitted-curated-source:role_forbidden", rendered)

    def test_rag_context_prompt_normalizes_uppercase_rag_citation_prefixes(self) -> None:
        pack = RagContextPack(
            query="uppercase rag citation prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "uppercase_prompt_chunk",
                    "Citation ID": "RAG:uppercase-prompt-source",
                    "title": "Uppercase prompt source",
                    "text": "Uppercase RAG citation prefixes should render canonically.",
                    "metadata": {"domain": "api_security"},
                }
            ],
            omitted_sources=[
                {
                    "Citation ID": "RAG:uppercase-omitted-source",
                    "reason": "role_forbidden",
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:uppercase-prompt-source]", rendered)
        self.assertIn("rag:uppercase-omitted-source:role_forbidden", rendered)
        self.assertNotIn("rag:RAG:", rendered)

    def test_rag_context_prompt_labels_direct_human_readable_metadata(self) -> None:
        pack = RagContextPack(
            query="display metadata prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_prompt_chunk",
                    "title": "Display prompt source",
                    "text": "Direct payloads should preserve display-key prompt labels.",
                    "metadata": {"Domain": "api_security", "Usage policy": "advisory_only"},
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("domain=api_security", rendered)
        self.assertIn("policy=advisory_only", rendered)

    def test_rag_context_prompt_labels_top_level_human_readable_metadata(self) -> None:
        pack = RagContextPack(
            query="top level display metadata prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "top_level_display_prompt_chunk",
                    "title": "Top-level display prompt source",
                    "text": "Top-level display metadata should preserve prompt labels.",
                    "Domain": "api_security",
                    "Usage policy": "taxonomy_only",
                    "metadata": {},
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("domain=api_security", rendered)
        self.assertIn("policy=taxonomy_only", rendered)

    def test_rag_context_prompt_uses_human_readable_metadata_citation_id(self) -> None:
        pack = RagContextPack(
            query="display citation prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_prompt_chunk",
                    "title": "Display prompt source",
                    "text": "Display-key citations should render as RAG source citations.",
                    "metadata": {
                        "Citation ID": "display-prompt-source",
                        "Domain": "api_security",
                    },
                }
            ],
            omitted_sources=[
                {
                    "chunk_id": "display_omitted_chunk",
                    "reason": "role_forbidden",
                    "metadata": {"Citation ID": "display-omitted-source"},
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:display-prompt-source]", rendered)
        self.assertIn("rag:display-omitted-source:role_forbidden", rendered)
        self.assertNotIn("[rag:display_prompt_chunk]", rendered)
        self.assertNotIn("rag:display_omitted_chunk:role_forbidden", rendered)

    def test_rag_context_prompt_uses_human_readable_retrieval_text(self) -> None:
        pack = RagContextPack(
            query="display retrieval text prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_text_chunk",
                    "title": "Display prompt source",
                    "metadata": {
                        "Citation ID": "display-text-source",
                        "Domain": "api_security",
                        "Retrieval text": "Display-key retrieval text must render in advisory prompt context.",
                    },
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:display-text-source]", rendered)
        self.assertIn("Display-key retrieval text must render in advisory prompt context.", rendered)

    def test_rag_context_prompt_uses_human_readable_raw_text(self) -> None:
        pack = RagContextPack(
            query="display raw text prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_raw_text_chunk",
                    "title": "Display raw prompt source",
                    "metadata": {
                        "Citation ID": "display-raw-text-source",
                        "Domain": "api_security",
                        "Raw text": "Display-key raw text must render in advisory prompt context.",
                    },
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:display-raw-text-source]", rendered)
        self.assertIn("Display-key raw text must render in advisory prompt context.", rendered)

    def test_rag_context_prompt_uses_human_readable_source_file_as_label(self) -> None:
        pack = RagContextPack(
            query="display source file prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_source_file_chunk",
                    "Citation ID": "display-source-file",
                    "Retrieval text": "Source-file-only context should still render an advisory source label.",
                    "metadata": {
                        "Domain": "api_security",
                        "Source file": "curated/display-source-file.md",
                    },
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn("[rag:display-source-file] curated/display-source-file.md", rendered)
        self.assertIn("Source-file-only context should still render an advisory source label.", rendered)

    def test_rag_context_prompt_combines_title_and_source_file_in_default_label(self) -> None:
        pack = RagContextPack(
            query="display source provenance prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_title_source_file_chunk",
                    "Citation ID": "display-title-source-file",
                    "Title": "Display prompt source title",
                    "Retrieval text": "Title-bearing context should still show source-file provenance.",
                    "metadata": {
                        "Domain": "api_security",
                        "Source file": "curated/display-title-source-file.md",
                    },
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn(
            "[rag:display-title-source-file] Display prompt source title (curated/display-title-source-file.md)",
            rendered,
        )
        self.assertIn("Title-bearing context should still show source-file provenance.", rendered)

    def test_rag_context_prompt_preserves_section_and_page_source_location(self) -> None:
        pack = RagContextPack(
            query="display section page prompt rendering",
            purpose="operator_answer",
            role="operator_chat",
            chunks=[
                {
                    "chunk_id": "display_section_page_chunk",
                    "Citation ID": "display-section-page-source",
                    "Title": "Display prompt source title",
                    "Retrieval text": "Section-bearing context should keep source location provenance.",
                    "metadata": {
                        "Domain": "api_security",
                        "Source file": "curated/display-section-page.md",
                        "Section": "Display prompt source section",
                        "Page start": 2,
                        "Page end": 3,
                    },
                }
            ],
        )

        rendered = pack.prompt_context()

        self.assertIn(
            "[rag:display-section-page-source] "
            "Display prompt source section (curated/display-section-page.md pp. 2-3)",
            rendered,
        )
        self.assertIn("Section-bearing context should keep source location provenance.", rendered)

__all__ = ["RagIngestionTestsPart4"]
