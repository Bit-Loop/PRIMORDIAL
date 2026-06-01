from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class DomainModelsStructureQualityTests(unittest.TestCase):
    def test_domain_models_module_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]
        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/domain/models.py"
            and record.kind == "module"
        ]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
