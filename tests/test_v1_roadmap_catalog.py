from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.loader import CatalogValidationError
from primordial.core.catalog.v1_roadmap import V1RoadmapCatalog


REPO_ROOT = Path(__file__).resolve().parents[1]


class V1RoadmapCatalogTests(unittest.TestCase):
    def test_todo_markdown_active_roadmap_is_migrated_to_typed_catalog(self) -> None:
        roadmap = V1RoadmapCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(roadmap.id, "primordial_real_v1")
        self.assertEqual(roadmap.source_path, "TODO-real-v1.md")
        self.assertEqual(roadmap.status, "active")
        self.assertIn("2026-05-08_file_review_tracker", roadmap.archived_sections)
        self.assertIn("postgres_pgvector_canonical_live_store", roadmap.locked_decisions)
        self.assertIn("ollama_standard_local_model_serving", roadmap.locked_decisions)
        self.assertIn("secure_web_gui_bearer_token", roadmap.locked_decisions)

    def test_immediate_execution_order_matches_numbered_phases(self) -> None:
        roadmap = V1RoadmapCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(roadmap.immediate_execution_order, tuple(phase.id for phase in roadmap.phases))
        self.assertEqual(
            roadmap.immediate_execution_order,
            (
                "remove_scaffold_paths",
                "production_storage_backbone",
                "local_model_runtime_ollama",
                "real_primitive_execution_lane",
                "caido_integration",
                "notion_integration",
                "discord_integration",
                "web_gui_security",
                "workflow_memory_hardening",
                "htb_first_real_workflow",
            ),
        )

    def test_acceptance_criteria_preserve_real_execution_and_safety_gates(self) -> None:
        roadmap = V1RoadmapCatalog(REPO_ROOT / "catalog" / "project").load()

        phase_by_id = {phase.id: phase for phase in roadmap.phases}
        self.assertIn("recon_and_analysis_evidence_comes_from_actual_tool_execution", phase_by_id["real_primitive_execution_lane"].acceptance_criteria)
        self.assertIn("token_rotation_works", phase_by_id["web_gui_security"].acceptance_criteria)
        self.assertIn("real_tool_output_for_pirate_htb", phase_by_id["htb_first_real_workflow"].acceptance_criteria)
        self.assertIn("anthropic_claude_api_execution", roadmap.explicit_deferrals)
        self.assertIn("mature_exploit_automation", roadmap.explicit_deferrals)

    def test_roadmap_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "v1_roadmap.yaml").write_text(
                "id: primordial_real_v1\n"
                "source_path: TODO-real-v1.md\n"
                "status: active\n"
                "last_updated: '2026-05-04'\n"
                "archived_sections: []\n"
                "locked_decisions: []\n"
                "model_storage: {}\n"
                "target_model_set: []\n"
                "explicit_deferrals: []\n"
                "immediate_execution_order: []\n"
                "phases: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                V1RoadmapCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
