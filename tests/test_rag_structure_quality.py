from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class RagStructureQualityTests(unittest.TestCase):
    def test_rag_modules_have_no_structure_violations(self) -> None:
        root = Path(__file__).resolve().parents[1]
        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path.startswith("primordial/core/rag/")
        ]

        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
