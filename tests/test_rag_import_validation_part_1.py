from __future__ import annotations

from tests.test_rag_import_validation_common import *


class RagImportRecordValidatorTestsPart1(RagImportRecordValidatorTestsBase):
    def test_source_path_keys_are_shared_with_generated_export_context(self) -> None:
        self.assertIs(SOURCE_PATH_METADATA_KEYS, GENERATED_EXPORT_PATH_KEYS)
        self.assertFalse(hasattr(rag_context, "GENERATED_EXPORT_PATH_KEYS"))
        self.assertLessEqual(
            {"file_path", "source_artifact_path", "source_name"},
            set(GENERATED_EXPORT_PATH_KEYS),
        )

    def test_prefers_row_level_citation_id_over_synthetic_chunk_citation(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_from_preprocessor",
            "citation_id": "rag:curated-source-ref",
            "source_type": "methodology_doc",
            "retrieval_text": "Curated source references must survive import validation.",
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={},
        )

        self.assertEqual(sink_validator.envelopes[0].ref, "rag:curated-source-ref")
        self.assertEqual(sink_validator.envelopes[0].citations, ["rag:curated-source-ref"])

    def test_normalizes_uppercase_rag_citation_prefix_in_validation_envelope(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_uppercase_citation",
            "Citation ID": "RAG:uppercase-import-source",
            "source_type": "methodology_doc",
            "retrieval_text": "Uppercase RAG citation prefixes must validate canonically.",
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={},
        )

        self.assertEqual(sink_validator.envelopes[0].ref, "rag:uppercase-import-source")
        self.assertEqual(sink_validator.envelopes[0].citations, ["rag:uppercase-import-source"])

    def test_preserves_human_readable_citation_id_over_synthetic_chunk_citation(self) -> None:
        cases = [
            (
                "row_citation_id",
                {"Citation ID": "rag:display-row-source-ref"},
                {},
            ),
            (
                "nested_citation_id",
                {"metadata": {"Citation ID": "display-nested-source-ref"}},
                {},
            ),
            (
                "row_nested_citation_id",
                {"audit": {"Citation ID": "display-row-nested-source-ref"}},
                {},
            ),
            (
                "import_citation_id",
                {},
                {"Citation ID": "display-import-source-ref"},
            ),
        ]

        for case_id, row_overrides, import_metadata in cases:
            sink_validator = _CapturingSinkValidator()
            record = {
                "chunk_id": f"chunk_display_citation_{case_id}",
                "source_type": "methodology_doc",
                "retrieval_text": "Display-key citation IDs must survive import validation.",
                **row_overrides,
            }
            with self.subTest(case=case_id):
                RagImportRecordValidator(sink_validator).validate_rag_index_record(
                    record,
                    domain="methodology_standards",
                    metadata=import_metadata,
                )

                self.assertNotEqual(
                    sink_validator.envelopes[0].ref,
                    f"rag:chunk_display_citation_{case_id}",
                )
                self.assertTrue(sink_validator.envelopes[0].ref.startswith("rag:"))

    def test_preserves_human_readable_chunk_id_as_synthetic_citation(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "Chunk ID": "chunk_display_synthetic_citation",
            "source_type": "methodology_doc",
            "retrieval_text": "Display-key chunk IDs must not degrade to unknown RAG citations.",
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={},
        )

        self.assertEqual(sink_validator.envelopes[0].ref, "rag:chunk_display_synthetic_citation")
        self.assertEqual(sink_validator.envelopes[0].citations, ["rag:chunk_display_synthetic_citation"])

    def test_preserves_row_level_nested_human_readable_chunk_id_as_synthetic_citation(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "audit": {"Chunk ID": "chunk_row_nested_display_synthetic_citation"},
            "source_type": "methodology_doc",
            "retrieval_text": "Nested display-key chunk IDs must not degrade to unknown RAG citations.",
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={},
        )

        self.assertEqual(sink_validator.envelopes[0].ref, "rag:chunk_row_nested_display_synthetic_citation")
        self.assertEqual(sink_validator.envelopes[0].citations, ["rag:chunk_row_nested_display_synthetic_citation"])

    def test_preserves_human_readable_source_id_as_synthetic_citation(self) -> None:
        cases = [
            ("row_source_id", {"Source ID": "display-source-doc"}),
            ("row_nested_source_id", {"audit": {"Source ID": "display-nested-source-doc"}}),
        ]

        for case_id, row_overrides in cases:
            sink_validator = _CapturingSinkValidator()
            record = {
                "source_type": "methodology_doc",
                "retrieval_text": "Source IDs must not degrade to unknown RAG citations.",
                **row_overrides,
            }
            with self.subTest(case=case_id):
                RagImportRecordValidator(sink_validator).validate_rag_index_record(
                    record,
                    domain="methodology_standards",
                    metadata={},
                )

                self.assertNotEqual(sink_validator.envelopes[0].ref, "rag:unknown")
                self.assertTrue(sink_validator.envelopes[0].ref.startswith("rag:display"))

    def test_allows_preprocessed_markdown_rows_as_methodology_advisory_rag(self) -> None:
        record = {
            "chunk_id": "chunk_markdown_methodology",
            "source_type": "markdown",
            "source_file": "owasp-api.md",
            "retrieval_text": "Markdown preprocessor rows are advisory methodology, not target truth.",
        }

        RagImportRecordValidator().validate_rag_index_record(
            record,
            domain="api_security",
            metadata={"corpus_type": "api_security"},
        )

    def test_allows_preprocessed_rows_without_source_type_as_methodology_advisory_rag(self) -> None:
        record = {
            "chunk_id": "chunk_missing_source_type",
            "source_file": "decision-procedures.pdf",
            "retrieval_text": "Rows without source_type remain advisory methodology by default.",
        }

        RagImportRecordValidator().validate_rag_index_record(
            record,
            domain="formal_methods",
            metadata={"corpus_type": "formal_methods"},
        )

    def test_preserves_human_readable_corpus_type_in_validation_envelope(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_display_corpus_validation",
            "source_file": "advisory/context.md",
            "retrieval_text": "Display-key corpus metadata must stay attached to validation envelopes.",
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={"Corpus type": "vuln_intel"},
        )

        envelope = sink_validator.envelopes[0]
        self.assertEqual(envelope.corpus, "vuln_intel")
        self.assertEqual(envelope.source_type, "vuln_intel")

    def test_preserves_row_level_writeup_corpus_type_in_validation_envelope(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_row_writeup_corpus_validation",
            "retrieval_text": "Row-level writeup corpus metadata must remain attached to validation envelopes.",
            "Corpus type": "HTB Writeup",
            "Writeup access policy": "Postmortem Only",
            "Purpose": "Postmortem",
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="ctf_benchmark",
            metadata={},
        )

        envelope = sink_validator.envelopes[0]
        self.assertEqual(envelope.corpus, "HTB Writeup")
        self.assertEqual(envelope.source_type, "writeup")

    def test_preserves_human_readable_retrieval_text_in_validation_envelope(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_display_retrieval_text_validation",
            "source_type": "methodology_doc",
            "Retrieval text": "Display-key retrieval text must stay attached to validation envelopes.",
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={},
        )

        self.assertEqual(
            sink_validator.envelopes[0].content,
            "Display-key retrieval text must stay attached to validation envelopes.",
        )

    def test_preserves_nested_human_readable_retrieval_text_in_validation_envelope(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_nested_display_retrieval_text_validation",
            "source_type": "methodology_doc",
            "metadata": {
                "Retrieval text": "Nested display-key retrieval text must stay attached to validation envelopes.",
            },
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={},
        )

        self.assertEqual(
            sink_validator.envelopes[0].content,
            "Nested display-key retrieval text must stay attached to validation envelopes.",
        )

__all__ = ["RagImportRecordValidatorTestsPart1"]
