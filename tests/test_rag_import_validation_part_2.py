from __future__ import annotations

from tests.test_rag_import_validation_common import *


class RagImportRecordValidatorTestsPart2(RagImportRecordValidatorTestsBase):
    def test_preserves_row_level_nested_human_readable_retrieval_text_in_validation_envelope(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_row_nested_display_retrieval_text_validation",
            "source_type": "methodology_doc",
            "audit": {
                "Retrieval text": "Row-level nested retrieval text must stay attached to validation envelopes.",
            },
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={},
        )

        self.assertEqual(
            sink_validator.envelopes[0].content,
            "Row-level nested retrieval text must stay attached to validation envelopes.",
        )

    def test_preserves_nested_human_readable_excerpt_in_validation_envelope(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_nested_display_excerpt_validation",
            "source_type": "methodology_doc",
            "metadata": {
                "Excerpt": "Nested display-key excerpt must stay attached to validation envelopes.",
            },
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={},
        )

        self.assertEqual(
            sink_validator.envelopes[0].content,
            "Nested display-key excerpt must stay attached to validation envelopes.",
        )

    def test_preserves_row_level_source_refs_in_validation_envelope(self) -> None:
        sink_validator = _CapturingSinkValidator()
        record = {
            "chunk_id": "chunk_row_source_refs_validation",
            "source_type": "methodology_doc",
            "retrieval_text": "Row-level source refs must reach validation sinks.",
            "source_refs": ["rag:curated-source"],
        }

        RagImportRecordValidator(sink_validator).validate_rag_index_record(
            record,
            domain="methodology_standards",
            metadata={},
        )

        self.assertEqual(sink_validator.envelopes[0].metadata["source_refs"], ["rag:curated-source"])

    def test_rejects_unsupported_row_level_source_refs(self) -> None:
        record = {
            "chunk_id": "chunk_row_unsupported_source_refs",
            "source_type": "methodology_doc",
            "retrieval_text": "RAG import provenance must not hide collaboration refs.",
            "source_refs": ["github:issue-42"],
        }

        with self.assertRaisesRegex(ValueError, "unsupported source_refs"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_unsupported_row_level_source_reference_alias(self) -> None:
        record = {
            "chunk_id": "chunk_row_unsupported_source_reference",
            "source_type": "methodology_doc",
            "retrieval_text": "RAG import source-reference aliases must not hide collaboration refs.",
            "Source reference": "github:issue-42",
        }

        with self.assertRaisesRegex(ValueError, "unsupported source_refs"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_unsupported_row_level_source_ref_display_alias(self) -> None:
        record = {
            "chunk_id": "chunk_row_unsupported_source_ref_display_alias",
            "source_type": "methodology_doc",
            "retrieval_text": "RAG import display source-ref aliases must not hide collaboration refs.",
            "Source ref": "github:issue-42",
        }

        with self.assertRaisesRegex(ValueError, "unsupported source_refs"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_unsupported_row_level_source_ref_camel_case_alias(self) -> None:
        record = {
            "chunk_id": "chunk_row_unsupported_source_ref_camel_case_alias",
            "source_type": "methodology_doc",
            "retrieval_text": "RAG import camelCase sourceRef aliases must not hide collaboration refs.",
            "sourceRef": "github:issue-42",
        }

        with self.assertRaisesRegex(ValueError, "unsupported source_refs"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_unsupported_source_reference_alias_when_source_refs_is_valid(self) -> None:
        record = {
            "chunk_id": "chunk_row_mixed_source_reference",
            "source_type": "methodology_doc",
            "retrieval_text": "RAG import must merge source-ref aliases before validation.",
            "source_refs": ["rag:chunk_row_mixed_source_reference"],
            "Source reference": "github:issue-42",
        }

        with self.assertRaisesRegex(ValueError, "unsupported source_refs"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_nested_row_level_source_reference_alias(self) -> None:
        record = {
            "chunk_id": "chunk_row_nested_source_reference",
            "source_type": "methodology_doc",
            "retrieval_text": "RAG import must not drop nested row-level source refs before validation.",
            "audit": {"Source reference": "github:issue-42"},
        }

        with self.assertRaisesRegex(ValueError, "unsupported source_refs"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_malformed_row_level_source_refs(self) -> None:
        record = {
            "chunk_id": "chunk_row_malformed_source_refs",
            "source_type": "methodology_doc",
            "retrieval_text": "Malformed RAG import provenance must not be stringified before sink validation.",
            "source_refs": ["rag:curated-source", 42],
        }

        with self.assertRaisesRegex(ValueError, "malformed source_refs"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_empty_ai_source_ref_suffix_even_when_cited(self) -> None:
        record = {
            "chunk_id": "chunk_empty_ai_source_ref_suffix",
            "citation_id": "rag:",
            "source_type": "methodology_doc",
            "retrieval_text": "AI-derived source refs must include a concrete source identifier.",
            "source_refs": ["rag:"],
        }

        with self.assertRaisesRegex(ValueError, "malformed source_refs"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_allows_preprocessed_vuln_intel_cards_as_vuln_intel_advisory_rag(self) -> None:
        record = {
            "chunk_id": "chunk_vuln_card",
            "source_type": "vulnerability_intel_card",
            "source_file": "CVE-2026-9000.vuln-intel-card",
            "retrieval_text": "Vulnerability-intel cards are advisory hints, not target truth.",
            "metadata": {"corpus_type": "vuln_intel"},
        }

        RagImportRecordValidator().validate_rag_index_record(
            record,
            domain="vuln_intel",
            metadata={"corpus_type": "vuln_intel"},
        )

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

__all__ = ["RagImportRecordValidatorTestsPart2"]
