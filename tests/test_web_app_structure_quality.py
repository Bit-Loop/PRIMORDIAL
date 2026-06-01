from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class WebAppStructureQualityTests(unittest.TestCase):
    def test_web_dispatch_is_not_oversized_after_route_extraction(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/web/app.py"
            and record.kind == "function"
            and record.name == "dispatch"
        ]
        self.assertEqual(records, [])

    def test_web_route_modules_have_no_structure_violations(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        route_paths = {
            "primordial/core/web/control_routes.py",
            "primordial/core/web/rag_routes.py",
            "primordial/core/web/routing.py",
        }
        records = [record for record in audit.records if record.path in route_paths]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
