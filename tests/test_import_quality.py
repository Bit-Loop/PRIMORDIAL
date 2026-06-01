from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from primordial.core.quality.imports import audit_imports, main


class ImportQualityTests(unittest.TestCase):
    def test_import_audit_reports_python_import_cycles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "pkg"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "alpha.py").write_text("from pkg import beta\n", encoding="utf-8")
            (package / "beta.py").write_text("import pkg.alpha\n", encoding="utf-8")

            audit = audit_imports(root)

        self.assertEqual(audit.summary["python_file_count"], 3)
        self.assertEqual(audit.summary["cycle_count"], 1)
        records = [record for record in audit.records if record.kind == "import_cycle"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].cycle, ("pkg.alpha", "pkg.beta", "pkg.alpha"))

    def test_import_audit_reports_forbidden_dependency_edges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            core = root / "primordial" / "core"
            app = root / "primordial" / "app"
            core.mkdir(parents=True)
            app.mkdir(parents=True)
            (root / "primordial" / "__init__.py").write_text("", encoding="utf-8")
            (core / "__init__.py").write_text("", encoding="utf-8")
            (app / "__init__.py").write_text("", encoding="utf-8")
            (core / "service.py").write_text("from primordial.app import runtime\n", encoding="utf-8")
            (app / "runtime.py").write_text("VALUE = 1\n", encoding="utf-8")

            audit = audit_imports(root, forbidden_edges=(("primordial.core", "primordial.app"),))

        self.assertEqual(audit.summary["forbidden_dependency_count"], 1)
        records = [record for record in audit.records if record.kind == "forbidden_dependency"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].importer, "primordial.core.service")
        self.assertEqual(records[0].imported, "primordial.app.runtime")

    def test_import_audit_allows_web_control_plane_to_import_runtime_facade(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            web = root / "primordial" / "core" / "web"
            app = root / "primordial" / "app"
            web.mkdir(parents=True)
            app.mkdir(parents=True)
            (root / "primordial" / "__init__.py").write_text("", encoding="utf-8")
            (root / "primordial" / "core" / "__init__.py").write_text("", encoding="utf-8")
            (web / "__init__.py").write_text("", encoding="utf-8")
            (app / "__init__.py").write_text("", encoding="utf-8")
            (web / "app.py").write_text("from primordial.app import runtime\n", encoding="utf-8")
            (app / "runtime.py").write_text("VALUE = 1\n", encoding="utf-8")

            audit = audit_imports(root)

        self.assertEqual(audit.summary["forbidden_dependency_count"], 0)

    def test_import_quality_cli_returns_failure_and_writes_json_for_violations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "pkg"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "left.py").write_text("import pkg.right\n", encoding="utf-8")
            (package / "right.py").write_text("import pkg.left\n", encoding="utf-8")
            output_path = root / "imports.json"

            result = main(["--root", str(root), "--json", str(output_path)])
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 1)
        self.assertEqual(payload["summary"]["cycle_count"], 1)
        self.assertEqual(payload["summary"]["violation_count"], 1)

    def test_import_quality_cli_returns_success_for_clean_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "pkg"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "clean.py").write_text("import json\n", encoding="utf-8")
            output_path = root / "imports.json"

            result = main(["--root", str(root), "--json", str(output_path)])
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertEqual(payload["summary"]["violation_count"], 0)


if __name__ == "__main__":
    unittest.main()
