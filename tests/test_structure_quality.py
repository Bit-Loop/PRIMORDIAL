from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from primordial.core.quality.structure import audit_structure, main


class StructureQualityTests(unittest.TestCase):
    def test_structure_audit_reports_file_function_and_class_size_violations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "pkg" / "oversized.py"
            source.parent.mkdir()
            source.write_text(
                "\n".join(
                    [
                        "def too_big_function():",
                        "    x = 1",
                        "    x += 1",
                        "    x += 1",
                        "    return x",
                        "",
                        "class TooBigClass:",
                        "    value = 1",
                        "    value = 2",
                        "    value = 3",
                        "    value = 4",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            audit = audit_structure(root, max_file_lines=5, max_function_lines=3, max_class_lines=4)

        self.assertEqual(audit.summary["python_file_count"], 1)
        self.assertEqual(audit.summary["violation_count"], 3)
        records = {(record.kind, record.name): record for record in audit.records}
        self.assertEqual(records[("module", "pkg/oversized.py")].line_count, 11)
        self.assertEqual(records[("function", "too_big_function")].line_count, 5)
        self.assertEqual(records[("class", "TooBigClass")].line_count, 5)

    def test_structure_audit_skips_runtime_vendor_and_cache_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel_path in (
                "runtime/generated.py",
                "node_modules/pkg/generated.py",
                ".venv/lib/generated.py",
                ".pytest_cache/generated.py",
            ):
                path = root / rel_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("def generated():\n    return 1\n", encoding="utf-8")

            audit = audit_structure(root, max_file_lines=1, max_function_lines=1, max_class_lines=1)

        self.assertEqual(audit.summary["python_file_count"], 0)
        self.assertEqual(audit.summary["violation_count"], 0)

    def test_structure_audit_skips_archived_goal_compiler(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "goal" / "archive" / "goal_compile.py"
            source.parent.mkdir(parents=True)
            source.write_text("x = 1\nx = 2\n", encoding="utf-8")

            audit = audit_structure(root, max_file_lines=1, max_function_lines=1, max_class_lines=1)

        self.assertEqual(audit.summary["python_file_count"], 0)
        self.assertEqual(audit.summary["violation_count"], 0)

    def test_structure_quality_cli_returns_failure_and_writes_json_for_violations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "large.py"
            source.write_text("x = 1\nx = 2\nx = 3\n", encoding="utf-8")
            output_path = root / "structure.json"

            result = main(["--root", str(root), "--max-file-lines", "2", "--json", str(output_path)])
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 1)
        self.assertEqual(payload["summary"]["violation_count"], 1)
        self.assertEqual(payload["records"][0]["kind"], "module")

    def test_structure_quality_cli_returns_success_for_clean_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "small.py").write_text("x = 1\n", encoding="utf-8")
            output_path = root / "structure.json"

            result = main(["--root", str(root), "--max-file-lines", "2", "--json", str(output_path)])
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertEqual(payload["summary"]["violation_count"], 0)

    def test_notion_adapter_has_no_structure_violations(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/adapters/notion.py"
        ]
        self.assertEqual(records, [])

    def test_runtime_import_scope_payload_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/app/runtime.py"
            and record.kind == "function"
            and record.name == "import_scope_payload"
        ]
        self.assertEqual(records, [])

    def test_runtime_module_and_class_are_bounded_after_composition_extraction(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/app/runtime.py"
            and record.kind in {"module", "class"}
        ]
        self.assertEqual(records, [])

    def test_runtime_composition_modules_have_no_structure_violations(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path.startswith("primordial/app/runtime_")
        ]
        self.assertEqual(records, [])

    def test_runtime_set_target_active_ip_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/app/runtime.py"
            and record.kind == "function"
            and record.name == "set_target_active_ip"
        ]
        self.assertEqual(records, [])

    def test_runtime_work_status_payload_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/app/runtime.py"
            and record.kind == "function"
            and record.name == "work_status_payload"
        ]
        self.assertEqual(records, [])

    def test_runtime_work_status_blockers_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/app/runtime.py"
            and record.kind == "function"
            and record.name == "_work_status_blockers"
        ]
        self.assertEqual(records, [])

    def test_runtime_synthesize_rag_answer_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/app/runtime.py"
            and record.kind == "function"
            and record.name == "synthesize_rag_answer"
        ]
        self.assertEqual(records, [])

    def test_runtime_ask_operator_ai_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/app/runtime.py"
            and record.kind == "function"
            and record.name == "ask_operator_ai"
        ]
        self.assertEqual(records, [])

    def test_runtime_caido_import_requests_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/app/runtime.py"
            and record.kind == "function"
            and record.name == "caido_import_requests"
        ]
        self.assertEqual(records, [])

    def test_runtime_evaluate_models_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/app/runtime.py"
            and record.kind == "function"
            and record.name == "evaluate_models"
        ]
        self.assertEqual(records, [])

    def test_runtime_deterministic_operator_answer_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/app/runtime.py"
            and record.kind == "function"
            and record.name == "_deterministic_operator_answer"
        ]
        self.assertEqual(records, [])

    def test_runtime_deterministic_direct_answers_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/app/runtime.py"
            and record.kind == "function"
            and record.name == "_deterministic_direct_answers"
        ]
        self.assertEqual(records, [])

    def test_runtime_read_gpu_metrics_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/app/runtime.py"
            and record.kind == "function"
            and record.name == "_read_gpu_metrics"
        ]
        self.assertEqual(records, [])

    def test_runtime_register_worker_runners_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/app/runtime.py"
            and record.kind == "function"
            and record.name == "_register_worker_runners"
        ]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
