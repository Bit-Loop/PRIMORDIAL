from __future__ import annotations

from tests.test_rag_import_validation_common import *


class RagImportRecordValidatorTestsPart4(RagImportRecordValidatorTestsBase):
    def test_preserves_human_readable_list_restrictions(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_display_list_restrictions",
            "source_type": "methodology_doc",
            "Invalid for": "prompt",
            "metadata": {"Valid for": ["report_writer", "methodology_advisor"]},
            "retrieval_text": "Display-key list restrictions must survive RAG import.",
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={"Valid for": ["report_writer"]},
        )

        self.assertEqual(sink_validator.envelopes[0].invalid_for, ["prompt"])
        self.assertEqual(sink_validator.envelopes[0].valid_for, ["report_writer"])

    def test_rejects_row_level_generated_export_origin(self) -> None:
        record = {
            "chunk_id": "chunk_generated_export",
            "source_type": "methodology_doc",
            "retrieval_text": "Generated exports must not re-enter active operational RAG.",
            "origin": "generated_export",
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_generated_export_source_file_paths_without_metadata_markers(self) -> None:
        records = [
            {
                "chunk_id": "chunk_notion_export_filename",
                "source_type": "markdown",
                "source_file": "notion-export.md",
                "retrieval_text": "Generated Notion export prose must not become active RAG.",
            },
            {
                "chunk_id": "chunk_generic_generated_export_filename",
                "source_type": "markdown",
                "source_file": "generated-export.md",
                "retrieval_text": "Generated export prose must not become active RAG by filename.",
            },
            {
                "chunk_id": "chunk_nested_generated_export_filename",
                "source_type": "markdown",
                "source_file": ["advisory/context.md", "generated-export.md"],
                "retrieval_text": "Generated export paths nested in metadata lists must not become active RAG.",
            },
            {
                "chunk_id": "chunk_findings_notion_export_path",
                "source_type": "markdown",
                "source_file": "findings/notion/helix.htb/notion-export.md",
                "retrieval_text": "Generated findings exports must not be laundered by preprocessed rows.",
            },
        ]

        for record in records:
            with self.subTest(record=record["chunk_id"]):
                with self.assertRaisesRegex(ValueError, "generated export"):
                    RagImportRecordValidator().validate_rag_index_record(
                        record,
                        domain="methodology_standards",
                        metadata={},
                    )

    def test_rejects_human_readable_generated_export_source_paths_without_metadata_markers(self) -> None:
        records = [
            {
                "chunk_id": "chunk_display_source_file",
                "source_type": "markdown",
                "Source file": "findings/notion/rag.htb/notion-export.md",
                "retrieval_text": "Display-key source metadata must not hide generated exports from import validation.",
            },
            {
                "chunk_id": "chunk_display_source_path",
                "source_type": "markdown",
                "Source path": "findings/notion/helix.htb/notion-export.md",
                "retrieval_text": "Human-readable source path metadata must still be denied.",
            },
        ]

        for record in records:
            with self.subTest(record=record["chunk_id"]):
                with self.assertRaisesRegex(ValueError, "generated export"):
                    RagImportRecordValidator().validate_rag_index_record(
                        record,
                        domain="methodology_standards",
                    metadata={},
                )

    def test_rejects_row_level_generated_export_file_path_alias_without_metadata_markers(self) -> None:
        record = {
            "chunk_id": "chunk_file_path_generated_export",
            "source_type": "markdown",
            "file_path": "findings/notion/rag.htb/notion-export.md",
            "retrieval_text": "Generated export file_path aliases must not become active operational RAG.",
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_row_level_generated_export_source_name_alias_without_metadata_markers(self) -> None:
        record = {
            "chunk_id": "chunk_source_name_generated_export",
            "source_type": "markdown",
            "source_name": "notion-export.md",
            "retrieval_text": "Generated export source_name aliases must not become active operational RAG.",
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_row_level_generated_export_source_artifact_path_without_metadata_markers(self) -> None:
        record = {
            "chunk_id": "chunk_source_artifact_path_generated_export",
            "source_type": "markdown",
            "source_artifact_path": "findings/notion/rag.htb/notion-export.md",
            "retrieval_text": "Generated export source_artifact_path values must not become active operational RAG.",
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_row_level_generated_export_artifact_path_without_metadata_markers(self) -> None:
        record = {
            "chunk_id": "chunk_artifact_path_generated_export",
            "source_type": "markdown",
            "artifact_path": "findings/notion/rag.htb/notion-export.md",
            "retrieval_text": "Generated export artifact_path values must not become active operational RAG.",
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_row_level_generated_export_artifact_paths_without_metadata_markers(self) -> None:
        record = {
            "chunk_id": "chunk_artifact_paths_generated_export",
            "source_type": "markdown",
            "artifact_paths": ["findings/notion/rag.htb/notion-export.md"],
            "retrieval_text": "Generated export artifact_paths values must not become active operational RAG.",
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_row_level_generated_export_checkpoint_paths_without_metadata_markers(self) -> None:
        record = {
            "chunk_id": "chunk_checkpoint_paths_generated_export",
            "source_type": "markdown",
            "checkpoint_paths": ["findings/notion/rag.htb/notion-export.md"],
            "retrieval_text": "Generated export checkpoint_paths values must not become active operational RAG.",
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_row_level_generated_export_path_in_unknown_scalar_metadata(self) -> None:
        record = {
            "chunk_id": "chunk_unknown_scalar_path_generated_export",
            "source_type": "markdown",
            "provenance_url": "https://example.invalid/findings/notion/rag.htb/notion-export.md",
            "retrieval_text": "Unknown row-level scalar provenance paths must not become active operational RAG.",
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_generated_export_source_urls_without_metadata_markers(self) -> None:
        records = [
            {
                "chunk_id": "chunk_source_url_generated_export",
                "source_type": "markdown",
                "source_url": "https://example.invalid/findings/notion/rag.htb/notion-export.md",
                "retrieval_text": "Generated export source URLs must not become active operational RAG.",
            },
            {
                "chunk_id": "chunk_source_url_query_filename_generated_export",
                "source_type": "markdown",
                "source_url": "https://example.invalid/downloads/notion-export.md?download=1",
                "retrieval_text": "Generated export source URL query strings must not hide export filenames.",
            },
            {
                "chunk_id": "chunk_source_url_encoded_path_generated_export",
                "source_type": "markdown",
                "source_url": "https://example.invalid/downloads/findings%2Fnotion%2Frag.htb%2Freport.md",
                "retrieval_text": "Generated export source URL encoded slashes must not hide findings/notion paths.",
            },
            {
                "chunk_id": "chunk_source_url_double_encoded_path_generated_export",
                "source_type": "markdown",
                "source_url": "https://example.invalid/downloads/findings%252Fnotion%252Frag.htb%252Freport.md",
                "retrieval_text": "Generated export source URL double-encoded slashes must not hide findings/notion paths.",
            },
            {
                "chunk_id": "chunk_source_url_query_path_generated_export",
                "source_type": "markdown",
                "source_url": "https://example.invalid/download?path=findings%2Fnotion%2Frag.htb%2Freport.md",
                "retrieval_text": "Generated export source URL query parameters must not hide findings/notion paths.",
            },
            {
                "chunk_id": "chunk_source_url_semicolon_path_generated_export",
                "source_type": "markdown",
                "source_url": "https://example.invalid/download;findings%2Fnotion%2Frag.htb%2Freport.md",
                "retrieval_text": "Generated export source URL semicolon path segments must not hide findings/notion paths.",
            },
            {
                "chunk_id": "chunk_source_url_matrix_param_generated_export",
                "source_type": "markdown",
                "source_url": "https://example.invalid/findings;v=1/notion/rag.htb/report.md",
                "retrieval_text": "Generated export source URL matrix parameters must not hide findings/notion paths.",
            },
        ]

        for record in records:
            with self.subTest(record=record["chunk_id"]):
                with self.assertRaisesRegex(ValueError, "generated export"):
                    RagImportRecordValidator().validate_rag_index_record(
                        record,
                        domain="methodology_standards",
                        metadata={},
                    )

__all__ = ["RagImportRecordValidatorTestsPart4"]
