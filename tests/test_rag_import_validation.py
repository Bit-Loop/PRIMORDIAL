from __future__ import annotations

import hashlib
import json
import unittest
from types import SimpleNamespace

from primordial.core.context.generated_exports import GENERATED_EXPORT_PATH_KEYS
from primordial.core.rag import context as rag_context
from primordial.core.rag.importer import RagChunkImporter, RagImportOptions
from primordial.core.rag.import_validation import RagImportRecordValidator, SOURCE_PATH_METADATA_KEYS


class RagImportRecordValidatorTests(unittest.TestCase):
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

    def test_rejects_nested_generated_export_source_url_lists_without_metadata_markers(self) -> None:
        record = {
            "chunk_id": "chunk_nested_source_url_list_generated_export",
            "source_type": "markdown",
            "metadata": {
                "provenance": {
                    "source_urls": ["https://example.invalid/findings/notion/rag.htb/notion-export.md"]
                }
            },
            "retrieval_text": "Nested generated export source URL lists must not become active operational RAG.",
        }

        with self.assertRaisesRegex(ValueError, "generated export"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="methodology_standards",
                metadata={},
            )

    def test_rejects_row_level_nested_generated_export_source_url_without_metadata_markers(self) -> None:
        record = {
            "chunk_id": "chunk_row_nested_source_url_generated_export",
            "source_type": "markdown",
            "audit": {
                "source_url": "https://example.invalid/findings/notion/rag.htb/notion-export.md",
            },
            "retrieval_text": "Row-level nested generated export URLs must not be dropped before validation.",
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

    def test_rejects_row_level_closed_book_mode_alias_writeup_policy(self) -> None:
        record = {
            "chunk_id": "chunk_closed_book_mode_writeup",
            "source_type": "writeup",
            "retrieval_text": "Closed-book mode aliases must not enter active operational RAG.",
            "benchmark_mode": "closed_book_mode",
        }

        with self.assertRaisesRegex(ValueError, "writeup in closed_book_mode"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_row_level_nested_closed_book_writeup_source_type(self) -> None:
        record = {
            "chunk_id": "chunk_row_nested_closed_book_writeup_source_type",
            "retrieval_text": "Nested row-level writeup source types must not bypass closed-book validation.",
            "audit": {
                "source_type": "writeup",
                "benchmark_mode": "closed_book",
            },
        }

        with self.assertRaisesRegex(ValueError, "writeup in closed_book"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_row_level_nested_closed_book_writeup_source_types(self) -> None:
        record = {
            "chunk_id": "chunk_row_nested_closed_book_writeup_source_types",
            "retrieval_text": "Nested plural writeup source types must not bypass closed-book validation.",
            "audit": {
                "source_types": ["writeup"],
                "benchmark_mode": "closed_book",
            },
        }

        with self.assertRaisesRegex(ValueError, "writeup in closed_book"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_row_level_nested_closed_book_writeup_source_types_even_when_ordered_after_advisory(self) -> None:
        record = {
            "chunk_id": "chunk_row_nested_ordered_closed_book_writeup_source_types",
            "retrieval_text": "Plural source types must not hide writeups behind advisory labels.",
            "audit": {
                "source_types": ["methodology_doc", "writeup"],
                "benchmark_mode": "closed_book",
            },
        }

        with self.assertRaisesRegex(ValueError, "writeup in closed_book"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_closed_book_writeup_corpus_without_explicit_source_type(self) -> None:
        record = {
            "chunk_id": "chunk_closed_book_writeup_corpus",
            "retrieval_text": "Closed-book writeup corpus rows must not hide behind methodology defaults.",
            "corpus_type": "htb_writeup",
            "benchmark_mode": "closed_book",
        }

        with self.assertRaisesRegex(ValueError, "writeup in closed_book"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_closed_book_writeup_corpus_markers_inside_list_metadata(self) -> None:
        cases = {
            "corpus_type": {
                "chunk_id": "chunk_closed_book_writeup_corpus_type_list",
                "retrieval_text": "List-valued corpus metadata must not hide writeup markers.",
                "corpus_type": ["methodology_standards", "htb_writeup"],
                "benchmark_mode": "closed_book",
            },
            "nested_domain": {
                "chunk_id": "chunk_closed_book_writeup_domain_list",
                "retrieval_text": "List-valued nested domains must not hide writeup markers.",
                "audit": {
                    "domain": ["methodology_standards", "htb_writeup"],
                    "benchmark_mode": "closed_book",
                },
            },
        }

        for name, record in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "writeup in closed_book"):
                RagImportRecordValidator().validate_rag_index_record(
                    record,
                    domain="ctf_benchmark",
                    metadata={},
                )

    def test_rejects_row_level_nested_closed_book_writeup_domain(self) -> None:
        record = {
            "chunk_id": "chunk_row_nested_closed_book_writeup_domain",
            "retrieval_text": "Nested row-level writeup domains must not bypass closed-book validation.",
            "audit": {
                "domain": "htb_writeup",
                "benchmark_mode": "closed_book",
            },
        }

        with self.assertRaisesRegex(ValueError, "writeup in closed_book"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_human_readable_postmortem_only_writeup_policy_outside_postmortem_scope(self) -> None:
        record = {
            "chunk_id": "chunk_display_postmortem_only_writeup",
            "source_type": "writeup",
            "retrieval_text": "Human-readable postmortem-only writeup policy must not be dropped.",
            "Writeup access policy": "Postmortem Only",
        }

        with self.assertRaisesRegex(ValueError, "postmortem_only"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_rejects_import_level_postmortem_only_writeup_policy_even_when_row_disagrees(self) -> None:
        record = {
            "chunk_id": "chunk_import_postmortem_only_writeup",
            "source_type": "writeup",
            "retrieval_text": "Import-level postmortem-only writeup policy must not be hidden by row metadata.",
            "writeup_access_policy": "allowed",
        }

        with self.assertRaisesRegex(ValueError, "postmortem_only"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={"writeup_access_policy": "postmortem_only"},
            )

    def test_rejects_row_level_nested_postmortem_only_writeup_policy(self) -> None:
        record = {
            "chunk_id": "chunk_row_nested_postmortem_only_writeup",
            "source_type": "writeup",
            "retrieval_text": "Nested row-level writeup policy must not bypass import validation.",
            "audit": {"writeup_access_policy": "postmortem_only"},
        }

        with self.assertRaisesRegex(ValueError, "postmortem_only"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )

    def test_allows_human_readable_postmortem_purpose_for_postmortem_only_writeups(self) -> None:
        record = {
            "chunk_id": "chunk_display_postmortem_purpose_writeup",
            "source_type": "writeup",
            "retrieval_text": "Postmortem-only writeups may be imported only for postmortem-scoped RAG.",
            "Writeup access policy": "Postmortem Only",
            "Purpose": "Postmortem",
        }

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

    def test_rejects_human_readable_authoritative_authority_markers(self) -> None:
        cases = [
            (
                "row_authority",
                {"Authority": "authoritative"},
                {},
            ),
            (
                "nested_authority",
                {"metadata": {"Authority": "canonical"}},
                {"authority": "advisory"},
            ),
            (
                "import_authority",
                {},
                {"Authority": "observed"},
            ),
        ]

        for case_id, row_overrides, import_metadata in cases:
            record = {
                "chunk_id": f"chunk_display_authority_{case_id}",
                "source_type": "methodology_doc",
                "retrieval_text": "Display-key authority markers must not enter active RAG.",
                **row_overrides,
            }
            with self.subTest(case=case_id):
                with self.assertRaisesRegex(ValueError, "authority"):
                    RagImportRecordValidator().validate_rag_index_record(
                        record,
                        domain="methodology_standards",
                        metadata=import_metadata,
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

    def test_rejects_import_level_closed_book_writeup_policy_even_when_row_disagrees(self) -> None:
        record = {
            "chunk_id": "chunk_import_closed_book_writeup_policy",
            "source_type": "writeup",
            "retrieval_text": "Import-level closed-book writeup policy must not be hidden by row metadata.",
            "writeup_access_policy": "allowed",
        }

        with self.assertRaisesRegex(ValueError, "writeup in closed_book"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={"writeup_access_policy": "closed_book"},
            )

    def test_rejects_list_valued_restrictive_writeup_safety_metadata(self) -> None:
        cases = {
            "benchmark_mode": (
                {
                    "chunk_id": "chunk_list_closed_book_writeup_mode",
                    "source_type": "writeup",
                    "retrieval_text": "List-valued benchmark mode must not hide closed-book markers.",
                    "benchmark_mode": ["open_book", "closed_book"],
                },
                "writeup in closed_book",
            ),
            "writeup_access_policy": (
                {
                    "chunk_id": "chunk_list_postmortem_only_writeup_policy",
                    "source_type": "writeup",
                    "retrieval_text": "List-valued writeup policy must not hide postmortem-only markers.",
                    "writeup_access_policy": ["allowed", "postmortem_only"],
                },
                "postmortem_only",
            ),
            "writeups_allowed": (
                {
                    "chunk_id": "chunk_list_writeups_allowed_false",
                    "source_type": "writeup",
                    "retrieval_text": "List-valued writeups_allowed must not hide false markers.",
                    "writeups_allowed": [True, False],
                },
                "writeup in <unspecified>",
            ),
        }

        for name, (record, message) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, message):
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

    def test_metadata_preserves_human_readable_citation_and_source_ids(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        cases = [
            (
                "row_ids",
                {
                    "chunk_id": "chunk_display_row_ids",
                    "Citation ID": "rag:display-row-citation",
                    "Source ID": "display-row-source",
                    "source_type": "markdown",
                },
                "rag:display-row-citation",
                "display-row-source",
            ),
            (
                "nested_ids",
                {
                    "chunk_id": "chunk_display_nested_ids",
                    "source_type": "markdown",
                    "metadata": {
                        "Citation ID": "display-nested-citation",
                        "Source ID": "display-nested-source",
                    },
                },
                "rag:display-nested-citation",
                "display-nested-source",
            ),
        ]

        for case_id, record, expected_citation, expected_doc_id in cases:
            with self.subTest(case=case_id):
                metadata = importer._metadata(record, domain="methodology_standards")

                self.assertEqual(metadata["citation_id"], expected_citation)
                self.assertEqual(metadata["doc_id"], expected_doc_id)

    def test_metadata_preserves_human_readable_source_fields(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        cases = [
            (
                "row_source_fields",
                {
                    "chunk_id": "chunk_display_row_source_fields",
                    "Source file": "findings/notion/rag.htb/notion-export.md",
                    "Source path": "findings/notion/rag.htb/notion-export.md",
                    "Source type": "generated_export",
                },
            ),
            (
                "nested_source_fields",
                {
                    "chunk_id": "chunk_display_nested_source_fields",
                    "metadata": {
                        "Source file": "findings/notion/helix.htb/notion-export.md",
                        "Source path": "findings/notion/helix.htb/notion-export.md",
                        "Source type": "generated_export",
                    },
                },
            ),
        ]

        for case_id, record in cases:
            with self.subTest(case=case_id):
                metadata = importer._metadata(record, domain="methodology_standards")

                self.assertTrue(metadata["source_file"].endswith("notion-export.md"))
                self.assertTrue(metadata["source_path"].endswith("notion-export.md"))
                self.assertEqual(metadata["source_type"], "generated_export")

    def test_filters_and_artifact_preserve_human_readable_source_fields(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "chunk_id": "chunk_display_source_artifact",
            "Source ID": "display-source-doc",
            "Source file": "findings/notion/rag.htb/notion-export.md",
            "Source path": "findings/notion/rag.htb/notion-export.md",
            "source_sha256": "c" * 64,
            "retrieval_text": "Display-key source provenance must not bypass importer source filtering.",
        }

        self.assertTrue(
            importer._record_matches_filters(
                record,
                RagImportOptions(
                    chunks_dir="unused",
                    source_files={"findings/notion/rag.htb/notion-export.md"},
                ),
            )
        )

        chunk = importer._chunk_from_record(record, target_id="target_rag_corpus")
        artifact = importer._artifact_for_record(record, target_id="target_rag_corpus")

        self.assertEqual(chunk.title, "findings/notion/rag.htb/notion-export.md")
        self.assertEqual(artifact.path, "rag-preprocess:findings/notion/rag.htb/notion-export.md")
        self.assertEqual(artifact.metadata["doc_id"], "display-source-doc")
        self.assertEqual(artifact.metadata["source_file"], "findings/notion/rag.htb/notion-export.md")
        self.assertEqual(artifact.metadata["source_path"], "findings/notion/rag.htb/notion-export.md")

    def test_filter_accepts_human_readable_corpus_type_domain(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "chunk_id": "chunk_display_domain_filter",
            "Corpus type": "HTB Writeup",
            "source_sha256": "d" * 64,
            "retrieval_text": "Display domain filters should find canonicalized writeup chunks.",
        }

        self.assertTrue(
            importer._record_matches_filters(
                record,
                RagImportOptions(
                    chunks_dir="unused",
                    domains={"HTB Writeup"},
                ),
            )
        )

    def test_artifact_preserves_human_readable_source_hash_and_corpus(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "chunk_id": "chunk_display_source_hash_artifact",
            "Source ID": "display-vuln-source",
            "Source file": "CVE-2026-9000.vuln-intel-card",
            "Source SHA256": "f" * 64,
            "Corpus type": ["vulnerability_intel"],
            "Retrieval text": "Display-key source hash and corpus must remain advisory provenance.",
        }

        artifact = importer._artifact_for_record(record, target_id="target_rag_corpus")
        metadata = importer._metadata(record, domain=importer._domain(record))

        self.assertEqual(artifact.sha256, "f" * 64)
        self.assertEqual(artifact.metadata["domain"], "vuln_intel")
        self.assertEqual(metadata["source_sha256"], "f" * 64)
        self.assertEqual(metadata["domain"], "vuln_intel")
        self.assertEqual(metadata["corpus_type"], "vuln_intel")

    def test_metadata_canonicalizes_human_readable_writeup_corpus_type(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "chunk_id": "chunk_display_writeup_corpus",
            "Source SHA256": "e" * 64,
            "Corpus type": "HTB Writeup",
            "Writeup access policy": "Postmortem Only",
            "Purpose": "Postmortem",
            "Retrieval text": "Display-key writeup corpus metadata must remain writeup-gated after import.",
        }

        domain = importer._domain(record)
        metadata = importer._metadata(record, domain=domain)

        self.assertEqual(domain, "htb_writeup")
        self.assertEqual(metadata["domain"], "htb_writeup")
        self.assertEqual(metadata["corpus_type"], "htb_writeup")

    def test_best_record_id_preserves_human_readable_failure_ids(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        cases = [
            ({"Chunk ID": "chunk_display_failure"}, "chunk_display_failure"),
            ({"Record ID": "record_display_failure"}, "record_display_failure"),
            ({"Doc ID": "doc_display_failure"}, "doc_display_failure"),
            ({"metadata": {"Source ID": "source_display_failure"}}, "source_display_failure"),
        ]

        for record, expected_id in cases:
            with self.subTest(record=record):
                self.assertEqual(importer._best_record_id(json.dumps(record)), expected_id)

    def test_chunk_preserves_human_readable_chunk_fields(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "Chunk ID": "chunk_display_chunk_fields",
            "Retrieval text": "Display-key chunk text must preserve advisory RAG provenance.",
            "Source SHA256": "d" * 64,
            "Chunk index": 3,
            "Token estimate": 9,
            "Title": "Display-key chunk title",
        }

        chunk = importer._chunk_from_record(record, target_id="target_rag_corpus")

        self.assertEqual(chunk.id, "chunk_display_chunk_fields")
        self.assertEqual(chunk.text, "Display-key chunk text must preserve advisory RAG provenance.")
        self.assertEqual(chunk.source_sha256, "d" * 64)
        self.assertEqual(chunk.chunk_index, 3)
        self.assertEqual(chunk.token_count, 9)
        self.assertEqual(chunk.title, "Display-key chunk title")

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

    def test_metadata_derives_citation_id_from_human_readable_chunk_fields(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "Source ID": "display-source-doc",
            "Source SHA256": "e" * 64,
            "Chunk index": 4,
            "Retrieval text": "Display-key chunk fields must produce stable RAG citations.",
        }
        canonical_record = {
            "source_id": "display-source-doc",
            "source_sha256": "e" * 64,
        }

        metadata = importer._metadata(record, domain="api_security")
        expected_chunk_id = importer._derive_chunk_id(canonical_record, record["Retrieval text"], 4)

        self.assertEqual(metadata["citation_id"], f"rag:{expected_chunk_id}")
        self.assertNotEqual(metadata["citation_id"], "rag:unknown")

    def test_metadata_preserves_human_readable_raw_text(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        raw_text = "Display-key raw advisory source text must remain hashable provenance."
        record = {
            "chunk_id": "chunk_display_raw_text",
            "source_type": "markdown",
            "Raw text": raw_text,
        }

        metadata = importer._metadata(record, domain="methodology_standards")

        self.assertEqual(metadata["raw_text"], raw_text)
        self.assertEqual(metadata["raw_text_sha256"], hashlib.sha256(raw_text.encode("utf-8")).hexdigest())

    def test_metadata_preserves_human_readable_domain_provenance(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        record = {
            "chunk_id": "chunk_display_domain_provenance",
            "Domain": "api_security",
            "Secondary domains": ["methodology_standards", "vuln_intel"],
        }

        metadata = importer._metadata(record, domain=importer._domain(record))

        self.assertEqual(metadata["domain"], "api_security")
        self.assertEqual(metadata["original_domain"], "api_security")
        self.assertEqual(metadata["secondary_domains"], ["methodology_standards", "vuln_intel"])

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

    def test_metadata_preserves_human_readable_policy_fields(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        cases = [
            (
                "row_policy_fields",
                {
                    "chunk_id": "chunk_display_row_policy_fields",
                    "Source refs": ["rag:display-row-source"],
                    "Ingest allowed": False,
                    "Operational retrieval allowed": False,
                    "Valid for": ["report_writer"],
                    "Invalid for": ["prompt"],
                },
            ),
            (
                "nested_policy_fields",
                {
                    "chunk_id": "chunk_display_nested_policy_fields",
                    "metadata": {
                        "Source refs": ["rag:display-nested-source"],
                        "Ingest allowed": False,
                        "Operational retrieval allowed": False,
                        "Valid for": ["methodology_advisor"],
                        "Invalid for": ["task_metadata"],
                    },
                },
            ),
        ]

        for case_id, record in cases:
            with self.subTest(case=case_id):
                metadata = importer._metadata(record, domain="methodology_standards")

                self.assertFalse(metadata["ingest_allowed"])
                self.assertFalse(metadata["operational_retrieval_allowed"])
                self.assertEqual(metadata["source_refs"], record.get("Source refs") or record["metadata"]["Source refs"])
                self.assertEqual(metadata["valid_for"], record.get("Valid for") or record["metadata"]["Valid for"])
                self.assertEqual(metadata["invalid_for"], record.get("Invalid for") or record["metadata"]["Invalid for"])

    def test_metadata_preserves_human_readable_visibility_defaults(self) -> None:
        importer = RagChunkImporter.__new__(RagChunkImporter)
        cases = [
            (
                "row_visibility_defaults",
                {
                    "chunk_id": "chunk_display_row_visibility_defaults",
                    "Authority level": "advisory",
                    "Chunk type": "guidance",
                    "Section path": ["Guidance", "Scope"],
                    "Page start": 4,
                    "Page end": 5,
                    "Risk level": "low",
                    "Planner visibility": "methodology_only",
                    "Requires authorized scope": False,
                    "Scope gate required": False,
                    "Requires operator approval": True,
                    "Allowed use modes": ["suggest_only"],
                    "Allowed contexts": ["methodology_hint"],
                    "License status": "redistributable",
                },
            ),
            (
                "nested_visibility_defaults",
                {
                    "chunk_id": "chunk_display_nested_visibility_defaults",
                    "metadata": {
                        "Authority level": "advisory",
                        "Chunk type": "guidance",
                        "Section path": ["Guidance", "Nested"],
                        "Page start": 6,
                        "Page end": 7,
                        "Risk level": "low",
                        "Planner visibility": "methodology_only",
                        "Requires authorized scope": False,
                        "Scope gate required": False,
                        "Requires operator approval": True,
                        "Allowed use modes": ["suggest_only"],
                        "Allowed contexts": ["methodology_hint"],
                        "License status": "redistributable",
                    },
                },
            ),
        ]

        for case_id, record in cases:
            expected = record.get("metadata", record)
            with self.subTest(case=case_id):
                metadata = importer._metadata(record, domain="methodology_standards")

                self.assertEqual(metadata["authority_level"], "advisory")
                self.assertEqual(metadata["chunk_type"], "guidance")
                self.assertEqual(metadata["section_path"], expected["Section path"])
                self.assertEqual(metadata["page_start"], expected["Page start"])
                self.assertEqual(metadata["page_end"], expected["Page end"])
                self.assertEqual(metadata["risk_level"], "low")
                self.assertEqual(metadata["planner_visibility"], "methodology_only")
                self.assertFalse(metadata["requires_authorized_scope"])
                self.assertFalse(metadata["scope_gate_required"])
                self.assertTrue(metadata["requires_operator_approval"])
                self.assertEqual(metadata["allowed_use_modes"], ["suggest_only"])
                self.assertEqual(metadata["allowed_contexts"], ["methodology_hint"])
                self.assertEqual(metadata["license_status"], "redistributable")


class _CapturingSinkValidator:
    def __init__(self) -> None:
        self.envelopes = []

    def validate(self, sink, envelopes):
        self.sink = sink
        self.envelopes = list(envelopes)
        return SimpleNamespace(valid=True, errors=[])


if __name__ == "__main__":
    unittest.main()
