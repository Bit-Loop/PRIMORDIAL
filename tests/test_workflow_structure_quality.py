from __future__ import annotations

from pathlib import Path
import unittest

from primordial.core.quality.structure import audit_structure


class WorkflowStructureQualityTests(unittest.TestCase):
    def test_workflow_module_and_class_are_bounded_after_composition_extraction(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/orchestration/workflow.py"
            and record.kind in {"module", "class"}
        ]
        self.assertEqual(records, [])

    def test_workflow_composition_modules_have_no_structure_violations(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path.startswith("primordial/core/orchestration/workflow_")
        ]
        self.assertEqual(records, [])

    def test_evaluate_target_methodology_state_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/orchestration/workflow.py"
            and record.kind == "function"
            and record.name == "_evaluate_target_methodology_state"
        ]
        self.assertEqual(records, [])

    def test_methodology_candidate_actions_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/orchestration/workflow.py"
            and record.kind == "function"
            and record.name == "_methodology_candidate_actions"
        ]
        self.assertEqual(records, [])

    def test_create_planner_uncertainty_escalation_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/orchestration/workflow.py"
            and record.kind == "function"
            and record.name == "create_planner_uncertainty_escalation"
        ]
        self.assertEqual(records, [])

    def test_evaluate_remote_review_admission_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/orchestration/workflow.py"
            and record.kind == "function"
            and record.name == "_evaluate_remote_review_admission"
        ]
        self.assertEqual(records, [])

    def test_evaluate_rag_hint_admission_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/orchestration/workflow.py"
            and record.kind == "function"
            and record.name == "_evaluate_rag_hint_admission"
        ]
        self.assertEqual(records, [])

    def test_execute_ready_tasks_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/orchestration/workflow.py"
            and record.kind == "function"
            and record.name == "_execute_ready_tasks"
        ]
        self.assertEqual(records, [])

    def test_persist_execution_result_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/orchestration/workflow.py"
            and record.kind == "function"
            and record.name == "_persist_execution_result"
        ]
        self.assertEqual(records, [])

    def test_persist_execution_exception_is_not_oversized(self) -> None:
        root = Path(__file__).resolve().parents[1]

        audit = audit_structure(root)

        records = [
            record
            for record in audit.records
            if record.path == "primordial/core/orchestration/workflow.py"
            and record.kind == "function"
            and record.name == "_persist_execution_exception"
        ]
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
