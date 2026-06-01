from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class FindingsContextStructureQualityTests(unittest.TestCase):
    def test_sync_target_export_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/findings_context.py"
            and record.kind == "function"
            and record.name == "sync_target_export"
        ]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
