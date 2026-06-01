from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.ai_agent_prd import AIAgentPrdCatalog
from primordial.core.catalog.loader import CatalogValidationError


REPO_ROOT = Path(__file__).resolve().parents[1]


class AIAgentPrdCatalogTests(unittest.TestCase):
    def test_prd_markdown_is_migrated_to_typed_product_requirements(self) -> None:
        prd = AIAgentPrdCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(prd.id, "ai_agent_orchestration_tui_prd")
        self.assertEqual(prd.source_path, "ai-agent-prd.md")
        self.assertEqual(prd.status, "draft_v0_migrated")
        self.assertIn("local_first_cli_tui_application", prd.overview)
        self.assertIn("methodology_driven_authorized_security_testing", prd.overview)
        self.assertIn("terminal_native_operator_cockpit", prd.vision)

    def test_prd_preserves_users_use_cases_and_non_goals(self) -> None:
        prd = AIAgentPrdCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertIn("individual_bug_bounty_hunters", prd.target_users)
        self.assertIn("ctf_hack_the_box_operators", prd.target_users)
        self.assertIn("import_hackerone_scope_and_normalize_targets", prd.primary_use_cases)
        self.assertIn("verify_multi_step_vulnerability_chains", prd.primary_use_cases)
        self.assertIn("fully_autonomous_unrestricted_offensive_action", prd.non_goals)
        self.assertIn("replacing_caido_as_http_testing_source_of_truth", prd.non_goals)

    def test_core_requirements_preserve_policy_context_and_primitive_boundaries(self) -> None:
        prd = AIAgentPrdCatalog(REPO_ROOT / "catalog" / "project").load()
        requirements = {item.id: item for item in prd.core_requirements}

        self.assertIn("scope_management", requirements)
        self.assertIn("enforce_in_scope_out_of_scope_policy_at_execution_time", requirements["scope_management"].requirements)
        self.assertIn("methodology_engine", requirements)
        self.assertIn("restrict_orchestrator_to_admissible_next_actions", requirements["methodology_engine"].requirements)
        self.assertIn("context_note_management", requirements)
        self.assertIn("keep_local_structured_storage_canonical", requirements["context_note_management"].requirements)
        self.assertIn("tool_primitive_management", requirements)
        self.assertIn("limit_model_visibility_to_approved_primitives", requirements["tool_primitive_management"].requirements)

    def test_architecture_corrections_are_deterministic_not_prompt_only(self) -> None:
        prd = AIAgentPrdCatalog(REPO_ROOT / "catalog" / "project").load()
        components = {item.id: item for item in prd.required_architecture_components}

        self.assertIn("action_policy_engine", components)
        self.assertIn("scope_binding", components["action_policy_engine"].capabilities)
        self.assertIn("approval_requirements", components["action_policy_engine"].capabilities)
        self.assertIn("durable_workflow_engine", components)
        self.assertIn("checkpoint_replay", components["durable_workflow_engine"].capabilities)
        self.assertIn("evidence_provenance_layer", components)
        self.assertIn("fact_to_evidence_lineage", components["evidence_provenance_layer"].capabilities)
        self.assertIn("from_multi_agent_prompts_to_deterministic_workflow_model_workers", prd.architecture_shifts)
        self.assertIn("from_llm_safety_judgment_to_policy_engine_decision", prd.architecture_shifts)

    def test_prd_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ai_agent_prd.yaml").write_text(
                "id: ai_agent_orchestration_tui_prd\n"
                "source_path: ai-agent-prd.md\n"
                "status: draft_v0_migrated\n"
                "last_updated: '2026-05-04'\n"
                "overview: []\n"
                "problem_statement: []\n"
                "vision: []\n"
                "target_users: []\n"
                "primary_use_cases: []\n"
                "non_goals: []\n"
                "core_requirements: []\n"
                "functional_components: []\n"
                "operating_model: []\n"
                "required_architecture_components: []\n"
                "architecture_shifts: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                AIAgentPrdCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
