from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class WebAppStructureQualityTests(unittest.TestCase):
    def test_web_app_module_and_class_are_bounded_after_mixin_extraction(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/web/app.py"
            and record.kind in {"module", "class"}
        ]
        self.assertEqual(records, [])

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

    def test_web_payload_wrappers_are_not_oversized_after_extraction(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/web/app.py"
            and record.kind == "function"
            and record.name in {"_control_plane_payload", "_traces_view"}
        ]
        self.assertEqual(records, [])

    def test_web_route_modules_have_no_structure_violations(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        route_paths = {
            "primordial/core/web/control_routes.py",
            "primordial/core/web/context_views.py",
            "primordial/core/web/integration_views.py",
            "primordial/core/web/payload_views.py",
            "primordial/core/web/rag_routes.py",
            "primordial/core/web/request_helpers.py",
            "primordial/core/web/responses.py",
            "primordial/core/web/routing.py",
            "primordial/core/web/runtime_actions.py",
            "primordial/core/web/runtime_views.py",
            "primordial/core/web/scope_views.py",
            "primordial/core/web/task_views.py",
            "primordial/core/web/workspace_views.py",
        }
        records = [record for record in audit.records if record.path in route_paths]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
