from __future__ import annotations

from tests.test_rag_import_validation_common import *


class RagImportRecordValidatorTestsPart6(RagImportRecordValidatorTestsBase):
    def test_rejects_plural_generated_export_origins(self) -> None:
        record = {
            "chunk_id": "chunk_plural_generated_export_origins",
            "source_type": "methodology_doc",
            "retrieval_text": "Plural generated export origin markers must not be hidden from validation.",
            "origins": ["generated_export"],
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_nested_generated_export_origin_even_when_import_metadata_disagrees(self) -> None:
        record = {
            "chunk_id": "chunk_masked_nested_generated_export",
            "source_type": "methodology_doc",
            "retrieval_text": "Import metadata must not launder row-level generated export markers.",
            "metadata": {"origin": "generated_export"},
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={"origin": "manual"},
            )

    def test_rejects_row_level_nested_generated_export_origin(self) -> None:
        record = {
            "chunk_id": "chunk_row_nested_generated_export_origin",
            "source_type": "methodology_doc",
            "retrieval_text": "Row-level nested generated export origins must not bypass import validation.",
            "audit": {"origin": "generated_export"},
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_import_level_generated_export_source_type_even_when_row_disagrees(self) -> None:
        record = {
            "chunk_id": "chunk_import_generated_export",
            "source_type": "methodology_doc",
            "retrieval_text": "Import-level generated export source markers must not be hidden by rows.",
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={"source_type": "generated_export"},
            )

    def test_rejects_plural_generated_export_source_types(self) -> None:
        record = {
            "chunk_id": "chunk_plural_generated_export_source_types",
            "source_type": "methodology_doc",
            "retrieval_text": "Plural generated export source markers must not be hidden from validation.",
            "source_types": ["generated_export"],
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_import_level_generated_export_kind_even_when_row_disagrees(self) -> None:
        record = {
            "chunk_id": "chunk_import_generated_export_kind",
            "kind": "rag",
            "source_type": "methodology_doc",
            "retrieval_text": "Import-level generated export kind markers must not be hidden by rows.",
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={"kind": "generated_export"},
            )

    def test_rejects_row_level_nested_generated_export_source_type(self) -> None:
        record = {
            "chunk_id": "chunk_row_nested_generated_export_source_type",
            "source_type": "methodology_doc",
            "retrieval_text": "Row-level nested generated export source types must not bypass import validation.",
            "audit": {"source_type": "generated_export"},
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_human_readable_generated_export_classification_markers(self) -> None:
        cases = [
            (
                "row_source_type",
                {"Source type": "generated_export"},
                {},
            ),
            (
                "row_kind",
                {"Kind": "generated_export"},
                {},
            ),
            (
                "nested_source_type",
                {"metadata": {"Source type": "generated_export"}},
                {"source_type": "methodology_doc"},
            ),
            (
                "nested_kind",
                {"metadata": {"Kind": "generated_export"}},
                {"kind": "rag"},
            ),
            (
                "import_source_type",
                {},
                {"Source type": "generated_export"},
            ),
            (
                "import_kind",
                {},
                {"Kind": "generated_export"},
            ),
        ]

        for case_id, row_overrides, import_metadata in cases:
            record = {
                "chunk_id": f"chunk_display_generated_export_{case_id}",
                "kind": "rag",
                "source_type": "methodology_doc",
                "retrieval_text": "Display-key generated export markers must not be laundered into RAG.",
                **row_overrides,
            }
            with self.subTest(case=case_id):
                with self.assertRaisesRegex(ValueError, "generated export"):
                    RagImportRecordValidator().validate_rag_index_record(
                        record,
                        domain="methodology_standards",
                        metadata=import_metadata,
                    )

    def test_rejects_nested_generated_export_source_type_even_when_import_metadata_disagrees(self) -> None:
        record = {
            "chunk_id": "chunk_nested_generated_export_source_type",
            "source_type": "methodology_doc",
            "retrieval_text": "Nested generated export source markers must not be hidden by import metadata.",
            "metadata": {"source_type": "generated_export"},
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={"source_type": "methodology_doc"},
            )

    def test_rejects_nested_generated_export_kind_even_when_import_metadata_disagrees(self) -> None:
        record = {
            "chunk_id": "chunk_nested_generated_export_kind",
            "kind": "rag",
            "source_type": "methodology_doc",
            "retrieval_text": "Nested generated export kind markers must not be hidden by import metadata.",
            "metadata": {"kind": "generated_export"},
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={"kind": "rag"},
            )

    def test_rejects_import_level_authoritative_authority_even_when_row_disagrees(self) -> None:
        record = {
            "chunk_id": "chunk_import_authoritative_authority",
            "authority": "advisory",
            "source_type": "methodology_doc",
            "retrieval_text": "Import-level authority markers must not be laundered into advisory RAG.",
        }

        with self.assertRaisesRegex(ValueError, "advisory authority"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={"authority": "authoritative"},
            )

    def test_rejects_nested_authoritative_authority_even_when_import_metadata_disagrees(self) -> None:
        record = {
            "chunk_id": "chunk_nested_authoritative_authority",
            "authority": "advisory",
            "source_type": "methodology_doc",
            "retrieval_text": "Nested authority markers must not be hidden by safer import metadata.",
            "metadata": {"authority": "authoritative"},
        }

        with self.assertRaisesRegex(ValueError, "advisory authority"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={"authority": "advisory"},
            )

    def test_rejects_row_level_nested_authoritative_authority(self) -> None:
        record = {
            "chunk_id": "chunk_row_nested_authoritative_authority",
            "source_type": "methodology_doc",
            "retrieval_text": "Nested row-level authority markers must not enter active RAG.",
            "audit": {"authority": "canonical"},
        }

        with self.assertRaisesRegex(ValueError, "advisory authority"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_preserves_row_level_nested_allowed_authority(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_row_nested_historical_authority",
            "source_type": "methodology_doc",
            "retrieval_text": "Nested row-level allowed authority must stay attached to validation envelopes.",
            "audit": {"authority": "historical"},
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={},
        )

        self.assertEqual(sink_validator.envelopes[0].authority, "historical")

__all__ = ["RagImportRecordValidatorTestsPart6"]
