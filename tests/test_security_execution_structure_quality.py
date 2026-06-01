from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class SecurityExecutionStructureQualityTests(unittest.TestCase):
    def test_security_execution_facade_has_no_structure_violations(self) -> None:
        root = Path(__file__).resolve().parents[1]
        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/modes/security/execution.py"
        ]

        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
