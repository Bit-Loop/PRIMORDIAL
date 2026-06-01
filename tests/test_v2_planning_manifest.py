from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.loader import CatalogValidationError
from primordial.core.catalog.v2_planning import V2PlanningManifestCatalog


REPO_ROOT = Path(__file__).resolve().parents[1]


class V2PlanningManifestTests(unittest.TestCase):
    def test_v2_readme_is_migrated_to_non_runtime_typed_manifest(self) -> None:
        manifest = V2PlanningManifestCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(manifest.id, "primordial_v2_planning")
        self.assertEqual(manifest.source_path, "docs/v2/README.md")
        self.assertEqual(manifest.status, "v2_preparation_only")
        self.assertFalse(manifest.loaded_by_v1_runtime)
        self.assertFalse(manifest.markdown_authoritative)
        self.assertIn("future_version_planning", manifest.purpose)
        self.assertIn("not_loaded_by_primordial_v1_runtime", manifest.boundaries)

    def test_v2_planning_manifest_preserves_artifact_inventory_and_integration_gate(self) -> None:
        manifest = V2PlanningManifestCatalog(REPO_ROOT / "catalog" / "project").load()
        artifacts = {artifact.path: artifact for artifact in manifest.artifacts}

        self.assertEqual(artifacts["docs/v2/reverse_engineering_framework.md"].kind, "planning_framework")
        self.assertIn("binary_exploitation_research", artifacts["docs/v2/reverse_engineering_framework.md"].domains)
        self.assertIn("fpga_reverse_engineering", artifacts["docs/v2/reverse_engineering_framework.md"].domains)
        self.assertEqual(artifacts["docs/v2/reverse_engineering_tooling.yaml"].kind, "structured_tooling_taxonomy")
        self.assertIn("expected_evidence_types", artifacts["docs/v2/reverse_engineering_tooling.yaml"].domains)
        self.assertEqual(artifacts["docs/v2/reverse_engineering_test_plan.md"].kind, "acceptance_test_plan")
        self.assertIn("policy_gates", artifacts["docs/v2/reverse_engineering_test_plan.md"].domains)

        self.assertEqual(
            manifest.future_integration_gate,
            (
                "dedicated_implementation_milestone",
                "move_selected_material_into_runtime_catalogs",
                "move_selected_material_into_storage_models",
                "move_selected_material_into_policy_gates",
                "move_selected_material_into_tests",
            ),
        )

    def test_v2_planning_manifest_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "v2_planning.yaml").write_text(
                "id: primordial_v2_planning\n"
                "source_path: docs/v2/README.md\n"
                "status: v2_preparation_only\n"
                "loaded_by_v1_runtime: false\n"
                "markdown_authoritative: false\n"
                "purpose: []\n"
                "boundaries: []\n"
                "artifacts: []\n"
                "future_integration_gate: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                V2PlanningManifestCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
