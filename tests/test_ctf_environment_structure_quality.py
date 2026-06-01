from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class CTFEnvironmentStructureQualityTests(unittest.TestCase):
    def test_environment_contract_modules_are_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1] / "primordial" / "labs" / "ctf"
        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path in {"environment.py", "environment_helpers.py"}
            and record.kind == "module"
        ]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
