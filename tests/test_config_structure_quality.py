from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class ConfigStructureQualityTests(unittest.TestCase):
    def test_app_config_from_env_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]
        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/config.py"
            and record.kind == "function"
            and record.name == "from_env"
        ]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
