from __future__ import annotations

from tests.test_rag_import_validation_common import *


class RagImportRecordValidatorTestsPart7(RagImportRecordValidatorTestsBase):
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

__all__ = ["RagImportRecordValidatorTestsPart7"]
