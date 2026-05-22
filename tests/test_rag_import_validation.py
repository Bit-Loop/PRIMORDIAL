from __future__ import annotations

import unittest
from types import SimpleNamespace

from primordial.core.rag.importer import RagChunkImporter
from primordial.core.rag.import_validation import RagImportRecordValidator


class RagImportRecordValidatorTests(unittest.TestCase):
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

    def test_rejects_row_level_hidden_solution_poison_flags(self) -> None:
        record = {
            "chunk_id": "chunk_hidden_solution",
            "source_type": "ctf_manifest",
            "retrieval_text": "Hidden solution material must not enter active operational RAG.",
            "poison_flags": ["hidden_solution_material"],
        }

        with self.assertRaisesRegex(ValueError, "hidden solution material"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_row_level_scalar_hidden_solution_poison_flags(self) -> None:
        record = {
            "chunk_id": "chunk_scalar_hidden_solution",
            "source_type": "ctf_manifest",
            "retrieval_text": "Scalar hidden solution flags must not be dropped during RAG import.",
            "poison_flags": "hidden_solution_material",
        }

        with self.assertRaisesRegex(ValueError, "hidden solution material"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_import_level_scalar_hidden_solution_poison_flags(self) -> None:
        record = {
            "chunk_id": "chunk_import_scalar_hidden_solution",
            "source_type": "ctf_manifest",
            "retrieval_text": "Scalar import-level poison flags must not be dropped during RAG import.",
        }

        with self.assertRaisesRegex(ValueError, "hidden solution material"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={"poison_flags": "hidden_solution_material"},
            )

    def test_rejects_import_level_tuple_hidden_solution_poison_flags(self) -> None:
        record = {
            "chunk_id": "chunk_import_tuple_hidden_solution",
            "source_type": "ctf_manifest",
            "retrieval_text": "Tuple import-level poison flags must not be dropped during RAG import.",
        }
        with self.assertRaisesRegex(ValueError, "hidden solution material"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={"poison_flags": ("hidden_solution_material",)},
            )

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

    def test_rejects_row_level_closed_book_writeup_policy(self) -> None:
        record = {
            "chunk_id": "chunk_closed_book_writeup",
            "source_type": "writeup",
            "retrieval_text": "Closed-book writeups must not enter active operational RAG.",
            "benchmark_mode": "closed_book",
        }

        with self.assertRaisesRegex(ValueError, "writeup in closed_book"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_nested_metadata_generated_export_origin(self) -> None:
        record = {
            "chunk_id": "chunk_nested_generated_export",
            "source_type": "methodology_doc",
            "retrieval_text": "Nested generated export markers must not be hidden from validation.",
            "metadata": {"origin": "generated_export"},
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

    def test_rejects_nested_metadata_closed_book_writeup_policy(self) -> None:
        record = {
            "chunk_id": "chunk_nested_closed_book_writeup",
            "source_type": "writeup",
            "retrieval_text": "Nested closed-book markers must not be hidden from validation.",
            "metadata": {"benchmark_mode": "closed_book"},
        }

        with self.assertRaisesRegex(ValueError, "writeup in closed_book"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_nested_metadata_denied_operational_retrieval(self) -> None:
        record = {
            "chunk_id": "chunk_nested_retrieval_denied",
            "source_type": "methodology_doc",
            "retrieval_text": "Nested operational retrieval denial must be preserved.",
            "metadata": {"operational_retrieval_allowed": False},
        }

        with self.assertRaisesRegex(ValueError, "operational_retrieval_allowed=false"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )


class RagChunkImporterMetadataTests(unittest.TestCase):
    def test_metadata_preserves_row_level_citation_id(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)

        metadata = importer._metadata(
            {
                "chunk_id": "chunk_from_preprocessor",
                "citation_id": "rag:curated-source-ref",
                "source_type": "markdown",
            },
            domain="methodology_standards",
        )

        self.assertEqual(metadata["citation_id"], "rag:curated-source-ref")

    def test_metadata_derives_citation_id_when_chunk_id_is_missing(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "doc_id": "source_api",
            "source_sha256": "b" * 64,
            "chunk_index": 2,
            "retrieval_text": "Derived chunks must not serialize placeholder rag citations.",
        }

        metadata = importer._metadata(record, domain="api_security")
        expected_chunk_id = importer._derive_chunk_id(record, record["retrieval_text"], 2)

        self.assertEqual(metadata["citation_id"], f"rag:{expected_chunk_id}")
        self.assertNotEqual(metadata["citation_id"], "rag:None")

    def test_metadata_preserves_row_level_invalid_for(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)

        metadata = importer._metadata(
            {
                "chunk_id": "prompt_denied_chunk",
                "source_type": "methodology_doc",
                "invalid_for": ["prompt"],
            },
            domain="methodology_standards",
        )

        self.assertEqual(metadata["invalid_for"], ["prompt"])

    def test_metadata_preserves_row_level_valid_for(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)

        metadata = importer._metadata(
            {
                "chunk_id": "report_only_chunk",
                "source_type": "methodology_doc",
                "valid_for": ["report_writer"],
            },
            domain="methodology_standards",
        )

        self.assertEqual(metadata["valid_for"], ["report_writer"])


class _CapturingSinkValidator:
    def __init__(self) -> None:
        self.envelopes = []

    def validate(self, sink, envelopes):
        self.sink = sink
        self.envelopes = list(envelopes)
        return SimpleNamespace(valid=True, errors=[])


if __name__ == "__main__":
    unittest.main()
