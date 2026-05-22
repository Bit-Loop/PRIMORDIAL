from __future__ import annotations

import unittest

from primordial.core.rag.import_validation import RagImportRecordValidator


class RagImportMetadataFlagNormalizationTests(unittest.TestCase):
    def test_rejects_row_level_numeric_truthy_raw_flag_metadata(self) -> None:
        record = {
            "chunk_id": "chunk_row_numeric_raw_flag",
            "source_type": "ctf_manifest",
            "retrieval_text": "Numeric truthy raw flag metadata must not be dropped during RAG import.",
            "contains_raw_flag": 1,
        }

        with self.assertRaisesRegex(ValueError, "raw sensitive material"):
            RagImportRecordValidator().validate_rag_index_record(
                record,
                domain="ctf_benchmark",
                metadata={},
            )


if __name__ == "__main__":
    unittest.main()
