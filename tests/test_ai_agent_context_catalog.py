from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.ai_agent_context import AIAgentContextCatalog
from primordial.core.catalog.loader import CatalogValidationError


REPO_ROOT = Path(__file__).resolve().parents[1]


class AIAgentContextCatalogTests(unittest.TestCase):
    def test_current_context_markdown_is_migrated_to_typed_planning_baseline(self) -> None:
        context = AIAgentContextCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(context.id, "ai_agent_current_context")
        self.assertEqual(context.source_path, "ai-agent-current-context.md")
        self.assertEqual(context.status, "migrated_planning_baseline")
        self.assertIn("authorized_security_workflow_orchestration", context.current_goals)
        self.assertIn("local_structured_storage_is_source_of_truth", context.architecture_principles)
        self.assertIn("typed_primitives_with_clear_schemas", context.architecture_principles)

    def test_context_layers_and_evidence_requirements_are_preserved(self) -> None:
        context = AIAgentContextCatalog(REPO_ROOT / "catalog" / "project").load()

        layer_ids = {layer.id for layer in context.context_layers}
        self.assertEqual(layer_ids, {"task_context", "shared_working_context", "episodic_memory", "semantic_memory"})
        self.assertIn("no_full_project_history_by_default", context.context_loading_rules)
        self.assertIn("source_references", context.evidence_claim_requirements)
        self.assertIn("target_scope_binding", context.evidence_claim_requirements)
        self.assertIn("verification_status", context.evidence_claim_requirements)
        self.assertIn("raw_intuition_alone", context.durable_fact_denials)

    def test_agent_roles_are_event_driven_and_bounded(self) -> None:
        context = AIAgentContextCatalog(REPO_ROOT / "catalog" / "project").load()
        roles = {role.id: role for role in context.agent_roles}

        self.assertEqual(roles["primary_orchestrator"].activation, "scheduler_controller")
        self.assertIn("new_scope", roles["primary_orchestrator"].triggers)
        self.assertIn("two_or_more_related_verified_interests", roles["vulnerability_chaining_worker"].triggers)
        self.assertIn("produces_verification_tasks_not_final_claims", roles["vulnerability_chaining_worker"].guardrails)
        self.assertIn("final_finding_candidate", roles["agent_behavior_verifier"].triggers)
        self.assertIn("task_completion", roles["memory_notes_worker"].triggers)

    def test_claude_escalation_is_selective_and_post_response_verification_is_required(self) -> None:
        context = AIAgentContextCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertIn("subtle_authorization_or_business_logic_interpretation", context.claude_escalation.triggers)
        self.assertIn("routine_summarization", context.claude_escalation.denials)
        self.assertIn("policy_and_budget_gate", context.claude_escalation.flow)
        self.assertIn("post_response_verification", context.claude_escalation.flow)
        self.assertIn("do_not_promote_claude_output_directly_to_durable_truth", context.claude_escalation.post_response_rules)

    def test_ai_agent_context_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ai_agent_current_context.yaml").write_text(
                "id: ai_agent_current_context\n"
                "source_path: ai-agent-current-context.md\n"
                "status: migrated_planning_baseline\n"
                "last_updated: '2026-05-04'\n"
                "current_goals: []\n"
                "user_intents: []\n"
                "architecture_principles: []\n"
                "model_strategy: {}\n"
                "agent_roles: []\n"
                "evidence_claim_requirements: []\n"
                "durable_fact_denials: []\n"
                "context_layers: []\n"
                "context_loading_rules: []\n"
                "communication_patterns: []\n"
                "efficiency_rules: []\n"
                "claude_escalation: {}\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                AIAgentContextCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
