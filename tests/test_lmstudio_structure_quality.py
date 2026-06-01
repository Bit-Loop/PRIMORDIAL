from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class LMStudioStructureQualityTests(unittest.TestCase):
    def test_client_class_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/providers/lmstudio.py"
            and record.kind == "class"
            and record.name == "LMStudioClient"
        ]
        self.assertEqual(records, [])

    def test_chat_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/providers/lmstudio.py"
            and record.kind == "function"
            and record.name == "chat"
        ]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
