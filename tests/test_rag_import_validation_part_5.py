from __future__ import annotations

from tests.test_rag_import_validation_common import *


class RagImportRecordValidatorTestsPart5(RagImportRecordValidatorTestsBase):
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

__all__ = ["RagImportRecordValidatorTestsPart5"]
