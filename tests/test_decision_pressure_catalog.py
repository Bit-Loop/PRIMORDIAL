from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.decision_pressure import DecisionPressureCatalog
from primordial.core.catalog.loader import CatalogValidationError


REPO_ROOT = Path(__file__).resolve().parents[1]


class DecisionPressureCatalogTests(unittest.TestCase):
    def test_conflicting_methodologies_markdown_is_migrated_to_typed_catalog(self) -> None:
        catalog = DecisionPressureCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(catalog.id, "conflicting_methodologies_decision_pressure_map")
        self.assertEqual(catalog.source_path, "docs/CONFLICTING_METHODOLOGIES.md")
        self.assertEqual(catalog.status, "migrated_design_pressure_context")
        self.assertEqual(catalog.authority, "advisory_design_context_not_runtime_policy")
        self.assertIn("control_plane_first_runtime_for_authorized_security_work", catalog.reading_frame)
        self.assertIn("layer_ownership_must_be_explicit", catalog.reading_frame)
        self.assertEqual(len(catalog.conflicts), 13)

    def test_summary_resolutions_preserve_core_tradeoffs(self) -> None:
        catalog = DecisionPressureCatalog(REPO_ROOT / "catalog" / "project").load()
        conflicts = {item.id: item for item in catalog.conflicts}

        self.assertEqual(
            conflicts["source_of_truth"].default_resolution,
            "durable_state_wins_for_behavior_chat_remains_context",
        )
        self.assertEqual(conflicts["autonomy"].default_resolution, "intent_gates_capability_escalation")
        self.assertEqual(
            conflicts["methodology_structure"].default_resolution,
            "explicit_task_run_fsms_planner_remains_evidence_derived",
        )
        self.assertEqual(
            conflicts["runtime_artifacts"].default_resolution,
            "runtime_artifacts_outside_source_control_by_default",
        )

    def test_autonomy_conflict_preserves_recon_default_and_lab_proof_guard(self) -> None:
        catalog = DecisionPressureCatalog(REPO_ROOT / "catalog" / "project").load()
        conflicts = {item.id: item for item in catalog.conflicts}
        autonomy = conflicts["autonomy"]

        self.assertEqual(autonomy.side_a.label, "recon_only_by_default")
        self.assertEqual(autonomy.side_b.label, "capable_security_workflow")
        self.assertIn("fails_closed", autonomy.side_a.pros)
        self.assertIn("supports_end_to_end_authorized_workflows", autonomy.side_b.pros)
        self.assertIn("recon_only_generic_durable_default", autonomy.resolution_guards)
        self.assertIn("environment_proof_required_for_lab_default_intent", autonomy.resolution_guards)
        self.assertIn("missing_intent_or_evidence_explains_blocked_work", autonomy.resolution_guards)

    def test_ai_and_policy_conflicts_do_not_grant_durable_authority_to_models(self) -> None:
        catalog = DecisionPressureCatalog(REPO_ROOT / "catalog" / "project").load()
        conflicts = {item.id: item for item in catalog.conflicts}

        ai_reasoning = conflicts["ai_reasoning"]
        self.assertEqual(ai_reasoning.side_a.label, "proposal_engine")
        self.assertEqual(ai_reasoning.side_b.label, "deterministic_authority")
        self.assertIn("ai_may_propose_deterministic_systems_admit", ai_reasoning.resolution_guards)
        self.assertIn("primitives_policy_evidence_and_intent_required_before_tasks", ai_reasoning.resolution_guards)

        model_eval = conflicts["model_evaluation"]
        self.assertIn("operator_action_required_for_model_role_mutation", model_eval.resolution_guards)
        self.assertIn("before_after_diff_and_rollback_required_for_apply_action", model_eval.resolution_guards)

    def test_cross_cutting_principles_are_machine_readable(self) -> None:
        catalog = DecisionPressureCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(
            catalog.cross_cutting_principles,
            (
                "authority_belongs_to_durable_state_not_prose",
                "ai_proposes_deterministic_systems_admit",
                "safety_defaults_fail_closed",
                "escalation_must_be_explicit",
                "refactors_preserve_semantics_first",
                "artifacts_inspectable_but_intentionally_durable",
            ),
        )

    def test_decision_pressure_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "decision_pressure.yaml").write_text(
                "id: conflicting_methodologies_decision_pressure_map\n"
                "source_path: docs/CONFLICTING_METHODOLOGIES.md\n"
                "status: migrated_design_pressure_context\n"
                "authority: advisory_design_context_not_runtime_policy\n"
                "reading_frame: []\n"
                "conflicts: []\n"
                "cross_cutting_principles: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                DecisionPressureCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
