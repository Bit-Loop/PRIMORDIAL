from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class ContextReportStructureQualityTests(unittest.TestCase):
    def test_report_sink_validator_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]
        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/context/report.py"
            and record.kind == "function"
            and record.name == "validate_report_sink"
        ]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
