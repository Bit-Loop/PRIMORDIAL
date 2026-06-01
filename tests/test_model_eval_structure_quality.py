from __future__ import annotations

import ast
from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


def _method_line_count(path: Path, class_name: str, method_name: str) -> int:
    module = ast.parse(path.read_text(encoding="utf-8"))
    for node in module.body:
        if not isinstance(node, ast.ClassDef) or node.name != class_name:
            continue
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name == method_name:
                return item.end_lineno - item.lineno + 1
    raise AssertionError(f"{class_name}.{method_name} was not found")


def _class_line_count(path: Path, class_name: str) -> int:
    module = ast.parse(path.read_text(encoding="utf-8"))
    for node in module.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return node.end_lineno - node.lineno + 1
    raise AssertionError(f"{class_name} was not found")


class ModelEvalStructureQualityTests(unittest.TestCase):
    def test_model_evaluation_service_ratcheted_below_current_size(self) -> None:
        root = Path(__file__).resolve().parents[1]
        path = root / "primordial/core/providers/model_eval.py"

        line_count = _class_line_count(path, "ModelEvaluationService")

        self.assertLessEqual(line_count, 690)

    def test_aggregate_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/providers/model_eval.py"
            and record.kind == "function"
            and record.name == "aggregate"
        ]
        self.assertEqual(records, [])

    def test_default_cases_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/providers/model_eval.py"
            and record.kind == "function"
            and record.name == "default_cases"
        ]
        self.assertEqual(records, [])

    def test_evaluate_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/providers/model_eval.py"
            and record.kind == "function"
            and record.name == "evaluate"
        ]
        self.assertEqual(records, [])

    def test_identify_models_is_below_function_target(self) -> None:
        root = Path(__file__).resolve().parents[1]
        path = root / "primordial/core/providers/model_eval.py"

        line_count = _method_line_count(path, "ModelEvaluationService", "identify_models")

        self.assertLessEqual(line_count, 50)

    def test_recommend_is_below_function_target(self) -> None:
        root = Path(__file__).resolve().parents[1]
        path = root / "primordial/core/providers/model_eval.py"

        line_count = _method_line_count(path, "ModelEvaluationService", "recommend")

        self.assertLessEqual(line_count, 50)

    def test_estimate_model_runtime_is_below_function_target(self) -> None:
        root = Path(__file__).resolve().parents[1]
        path = root / "primordial/core/providers/model_eval.py"

        line_count = _method_line_count(path, "ModelEvaluationService", "_estimate_model_runtime")

        self.assertLessEqual(line_count, 50)

    def test_role_suggestion_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/providers/model_eval.py"
            and record.kind == "function"
            and record.name == "_role_suggestion"
        ]
        self.assertEqual(records, [])

    def test_role_findings_is_below_function_target(self) -> None:
        root = Path(__file__).resolve().parents[1]
        path = root / "primordial/core/providers/model_eval.py"

        line_count = _method_line_count(path, "ModelEvaluationService", "role_findings")

        self.assertLessEqual(line_count, 50)

    def test_score_output_is_below_function_target(self) -> None:
        root = Path(__file__).resolve().parents[1]
        path = root / "primordial/core/providers/model_eval.py"

        line_count = _method_line_count(path, "ModelEvaluationService", "score_output")

        self.assertLessEqual(line_count, 50)

    def test_write_artifacts_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/providers/model_eval.py"
            and record.kind == "function"
            and record.name == "write_artifacts"
        ]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
