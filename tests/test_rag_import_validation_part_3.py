from __future__ import annotations

from tests.test_rag_import_validation_common import *


class RagImportRecordValidatorTestsPart3(RagImportRecordValidatorTestsBase):
    def test_rejects_nested_scalar_hidden_solution_poison_flags(self) -> None:
        record = {
            "chunk_id": "chunk_nested_scalar_hidden_solution",
            "source_type": "ctf_manifest",
            "retrieval_text": "Scalar nested poison flags must not be dropped during RAG import.",
            "metadata": {"poison_flags": "hidden_solution_material"},
        }

        with self.assertRaisesRegex(ValueError, "hidden solution material"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_import_level_hidden_solution_poison_flags_even_when_row_disagrees(self) -> None:
        record = {
            "chunk_id": "chunk_masked_import_hidden_solution",
            "source_type": "ctf_manifest",
            "retrieval_text": "Import-level poison flags must not be hidden by row metadata.",
            "poison_flags": [],
        }

        with self.assertRaisesRegex(ValueError, "hidden solution material"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={"poison_flags": ["hidden_solution_material"]},
            )

    def test_rejects_nested_hidden_solution_poison_flags_even_when_row_disagrees(self) -> None:
        record = {
            "chunk_id": "chunk_masked_nested_hidden_solution",
            "source_type": "ctf_manifest",
            "retrieval_text": "Nested poison flags must not be hidden by row metadata.",
            "metadata": {"poison_flags": ["hidden_solution_material"]},
            "poison_flags": [],
        }

        with self.assertRaisesRegex(ValueError, "hidden solution material"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_nested_hidden_solution_poison_flags_even_when_import_metadata_disagrees(self) -> None:
        record = {
            "chunk_id": "chunk_import_masked_nested_hidden_solution",
            "source_type": "ctf_manifest",
            "retrieval_text": "Import metadata must not hide nested poison flags.",
            "metadata": {"poison_flags": ["hidden_solution_material"]},
            "poison_flags": [],
        }

        with self.assertRaisesRegex(ValueError, "hidden solution material"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={"poison_flags": []},
            )

    def test_rejects_row_level_nested_hidden_solution_poison_flags(self) -> None:
        record = {
            "chunk_id": "chunk_row_nested_hidden_solution_poison_flags",
            "source_type": "ctf_manifest",
            "retrieval_text": "Nested row-level poison flags must not bypass import validation.",
            "audit": {"poison_flags": ["hidden_solution_material"]},
        }

        with self.assertRaisesRegex(ValueError, "hidden solution material"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_human_readable_hidden_solution_poison_flags(self) -> None:
        cases = [
            (
                "row_poison_flags",
                {"Poison flags": ["hidden_solution_material"]},
                {},
            ),
            (
                "nested_poison_flags",
                {"metadata": {"Poison flags": "hidden_solution_material"}},
                {"poison_flags": []},
            ),
            (
                "import_poison_flags",
                {},
                {"Poison flags": ("hidden_solution_material",)},
            ),
        ]

        for case_id, row_overrides, import_metadata in cases:
            record = {
                "chunk_id": f"chunk_display_poison_flags_{case_id}",
                "source_type": "ctf_manifest",
                "retrieval_text": "Display-key poison flags must not hide closed-book material.",
                **row_overrides,
            }
            with self.subTest(case=case_id):
                with self.assertRaisesRegex(ValueError, "hidden solution material"):
                    RagImportRecordValidator().validate_rag_index_record(
                        record,
                        domain="ctf_benchmark",
                        metadata=import_metadata,
                    )

    def test_rejects_row_level_hidden_solution_metadata_flag(self) -> None:
        record = {
            "chunk_id": "chunk_row_hidden_solution_metadata",
            "source_type": "ctf_manifest",
            "retrieval_text": "Row-level hidden solution metadata must not be dropped before validation.",
            "hidden_solution_material": True,
        }

        with self.assertRaisesRegex(ValueError, "hidden solution material"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_row_level_nested_hidden_solution_metadata_flag(self) -> None:
        record = {
            "chunk_id": "chunk_row_nested_hidden_solution_metadata",
            "source_type": "ctf_manifest",
            "retrieval_text": "Nested row-level hidden solution metadata must not bypass validation.",
            "audit": {"hidden_solution_material": True},
        }

        with self.assertRaisesRegex(ValueError, "hidden solution material"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_row_level_raw_flag_metadata_flag(self) -> None:
        record = {
            "chunk_id": "chunk_row_raw_flag_metadata",
            "source_type": "ctf_manifest",
            "retrieval_text": "Row-level raw flag metadata must not be dropped before validation.",
            "contains_raw_flag": "yes",
        }

        with self.assertRaisesRegex(ValueError, "raw sensitive material"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_preserves_import_level_invalid_for_even_when_row_disagrees(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_import_invalid_for_prompt",
            "source_type": "methodology_doc",
            "retrieval_text": "Prompt-denied advisory context must stay prompt-denied during validation.",
            "invalid_for": [],
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={"invalid_for": ["prompt"]},
        )

        self.assertEqual(sink_validator.envelopes[0].invalid_for, ["prompt"])

    def test_preserves_nested_invalid_for_even_when_import_metadata_disagrees(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_nested_invalid_for_prompt",
            "source_type": "methodology_doc",
            "retrieval_text": "Nested prompt-denied advisory context must stay prompt-denied during validation.",
            "metadata": {"invalid_for": ["prompt"]},
            "invalid_for": [],
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={"invalid_for": []},
        )

        self.assertEqual(sink_validator.envelopes[0].invalid_for, ["prompt"])

    def test_preserves_import_level_valid_for_even_when_row_disagrees(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_import_valid_for_report",
            "source_type": "methodology_doc",
            "retrieval_text": "Report-only advisory context must not become unrestricted during validation.",
            "valid_for": [],
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={"valid_for": ["report_writer"]},
        )

        self.assertEqual(sink_validator.envelopes[0].valid_for, ["report_writer"])

    def test_preserves_nested_valid_for_even_when_import_metadata_disagrees(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_nested_valid_for_report",
            "source_type": "methodology_doc",
            "retrieval_text": "Nested report-only advisory context must not become unrestricted during validation.",
            "metadata": {"valid_for": ["report_writer"]},
            "valid_for": [],
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={"valid_for": []},
        )

        self.assertEqual(sink_validator.envelopes[0].valid_for, ["report_writer"])

    def test_preserves_row_level_nested_valid_for(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_row_nested_valid_for_report",
            "source_type": "methodology_doc",
            "retrieval_text": "Nested row-level valid_for restrictions must not become unrestricted.",
            "audit": {"valid_for": ["report_writer"]},
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={},
        )

        self.assertEqual(sink_validator.envelopes[0].valid_for, ["report_writer"])

__all__ = ["RagImportRecordValidatorTestsPart3"]
