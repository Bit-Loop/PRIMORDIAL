from __future__ import annotations

import unittest

from primordial.core.rag.import_validation import RagImportRecordValidator


class RagImportMetadataListNormalizationTests(unittest.TestCase):
    def test_rejects_import_level_set_hidden_solution_poison_flags(self) -> None:
        record = {
            "chunk_id": "chunk_import_set_hidden_solution",
            "source_type": "ctf_manifest",
            "retrieval_text": "Set import-level poison flags must not be dropped during RAG import.",
        }

        with self.assertRaisesRegex(ValueError, "hidden solution material"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={"poison_flags": {"hidden_solution_material"}},
            )

    def test_rejects_mapping_poison_flags_instead_of_dropping_them(self) -> None:
        record = {
            "chunk_id": "chunk_import_mapping_poison_flags",
            "source_type": "ctf_manifest",
            "retrieval_text": "Mapping poison flags must fail closed during RAG import.",
        }

        with self.assertRaisesRegex(ValueError, "poison_flags"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={"poison_flags": {"hidden_solution_material": True}},
            )


if __name__ == "__main__":
    unittest.main()
