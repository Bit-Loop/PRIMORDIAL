from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.human_change_safety import HumanChangeSafetyCatalog
from primordial.core.catalog.loader import CatalogValidationError


REPO_ROOT = Path(__file__).resolve().parents[1]


class HumanChangeSafetyCatalogTests(unittest.TestCase):
    def test_human_change_guide_is_migrated_to_typed_safety_catalog(self) -> None:
        catalog = HumanChangeSafetyCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(catalog.id, "primordial_human_change_safety")
        self.assertEqual(catalog.source_path, "docs/HUMAN_CHANGE_GUIDE.md")
        self.assertEqual(catalog.status, "migrated")
        self.assertEqual(catalog.authority, "typed_engineering_workflow_not_runtime_policy")
        self.assertEqual(
            catalog.execution_order,
            (
                "deterministic_planning",
                "deterministic_policy_admission",
                "bounded_execution",
                "evidence_write_back",
                "bounded_ai_review_or_proposal",
                "deterministic_verification",
            ),
        )

    def test_core_rules_preserve_deterministic_and_generation_safety_boundaries(self) -> None:
        catalog = HumanChangeSafetyCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertIn("runtime_facade_for_operator_facing_behavior", catalog.core_rules)
        self.assertIn("database_is_source_of_truth", catalog.core_rules)
        self.assertIn("active_ip_and_generation_are_safety_critical", catalog.core_rules)
        self.assertIn("ui_must_not_own_business_logic", catalog.core_rules)
        self.assertIn("ai_output_requires_deterministic_checks_and_evidence_before_durable_truth", catalog.core_rules)
        self.assertIn("do_not_bypass_scope_policy_or_generation_filters", catalog.core_rules)
        self.assertIn("do_not_mix_historical_target_evidence_into_current_active_ip_reasoning", catalog.core_rules)

    def test_authority_layers_and_validation_commands_are_explicit(self) -> None:
        catalog = HumanChangeSafetyCatalog(REPO_ROOT / "catalog" / "project").load()
        layers = {layer.id: layer.path for layer in catalog.authority_layers}

        self.assertEqual(layers["runtime_facade"], "primordial/app/runtime.py")
        self.assertEqual(layers["workflow_planning"], "primordial/core/orchestration/workflow.py")
        self.assertEqual(layers["policy"], "primordial/core/orchestration/policy.py")
        self.assertEqual(layers["verifier"], "primordial/core/orchestration/verifier.py")
        self.assertEqual(layers["execution"], "primordial/modes/security/execution.py")
        self.assertEqual(layers["web_api"], "primordial/core/web/app.py")
        self.assertIn("python3 -m unittest discover -s tests -t . -v", catalog.validation_commands)
        self.assertIn("node --check primordial/core/web/static/app.js", catalog.validation_commands)

    def test_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "human_change_safety.yaml").write_text(
                "id: primordial_human_change_safety\n"
                "source_path: docs/HUMAN_CHANGE_GUIDE.md\n"
                "status: migrated\n"
                "authority: typed_engineering_workflow_not_runtime_policy\n"
                "execution_order: []\n"
                "core_rules: []\n"
                "change_types: []\n"
                "authority_layers: []\n"
                "validation_commands: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                HumanChangeSafetyCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
