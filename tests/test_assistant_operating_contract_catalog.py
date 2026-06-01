from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.assistant_operating_contract import AssistantOperatingContractCatalog
from primordial.core.catalog.loader import CatalogValidationError


REPO_ROOT = Path(__file__).resolve().parents[1]


class AssistantOperatingContractCatalogTests(unittest.TestCase):
    def test_claude_guidance_sources_are_migrated_to_typed_contract(self) -> None:
        contract = AssistantOperatingContractCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(contract.id, "primordial_assistant_operating_contract")
        self.assertEqual(contract.source_paths, ("CLAUDE.md", "claude-instructions.md"))
        self.assertEqual(contract.status, "migrated")
        self.assertEqual(contract.authority, "typed_assistant_guidance_not_runtime_state")
        self.assertIn("local_first_control_plane", contract.project_model)
        self.assertIn("authorized_security_testing_only", contract.project_model)
        self.assertIn("no_risky_action_without_policy_evaluation", contract.invariants)
        self.assertIn("no_durable_fact_without_evidence_provenance_confidence_and_freshness", contract.invariants)
        self.assertIn("ai_output_is_advisory_and_deterministic_checks_gate_decisions", contract.invariants)
        self.assertIn("no_full_engagement_history_by_default", contract.invariants)
        self.assertIn("explicit_scope_required_before_task_execution", contract.invariants)

    def test_layer_order_tick_model_and_validation_commands_are_preserved(self) -> None:
        contract = AssistantOperatingContractCatalog(REPO_ROOT / "catalog" / "project").load()
        layer_paths = {layer.id: layer.path for layer in contract.layer_map}

        self.assertEqual(contract.layer_order[0], "domain_models")
        self.assertEqual(contract.layer_order[-1], "ui_surfaces")
        self.assertEqual(layer_paths["runtime_facade"], "primordial/app/runtime.py")
        self.assertEqual(layer_paths["policy"], "primordial/core/orchestration/policy.py")
        self.assertEqual(layer_paths["web_frontend"], "primordial/core/web/static/")
        self.assertIn("bounded_ticks_not_unbounded_loops", contract.execution_model)
        self.assertIn("continuous_mode_repeats_bounded_ticks", contract.execution_model)
        self.assertIn("python3 -m unittest discover -s tests -t . -v", contract.validation_commands)
        self.assertIn("python3 -m py_compile primordial/app/runtime.py primordial/core/orchestration/workflow.py primordial/modes/security/execution.py", contract.validation_commands)
        self.assertIn("node --check primordial/core/web/static/app.js", contract.validation_commands)

    def test_trace_resource_tooling_and_concurrency_rules_are_explicit(self) -> None:
        contract = AssistantOperatingContractCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertIn("model_name", contract.required_trace_metadata)
        self.assertIn("role_name", contract.required_trace_metadata)
        self.assertIn("evidence_quality", contract.required_trace_metadata)
        self.assertIn("manifest_and_health_check_required_before_assuming_tool_exists", contract.tooling_inventory_rules)
        self.assertIn("tool_awareness_feeds_task_generation_methodology_and_model_routing", contract.tooling_inventory_rules)
        self.assertIn("hard_token_usage_limits_per_task", contract.resource_budget_rules)
        self.assertIn("execution_time_ceiling_per_task_and_workflow", contract.resource_budget_rules)
        self.assertIn("retry_requires_explicit_justification", contract.resource_budget_rules)
        self.assertIn("bounded_pipeline_stages_with_inputs_outputs_exit_conditions_and_evidence", contract.concurrency_rules)
        self.assertIn("parallel_work_only_when_dependencies_do_not_conflict", contract.concurrency_rules)
        self.assertIn("concurrency_must_not_destroy_traceability", contract.concurrency_rules)

    def test_methodology_and_markdown_conflict_resolution_are_typed(self) -> None:
        contract = AssistantOperatingContractCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertIn("structured_phases_not_paragraphs", contract.methodology_rules)
        self.assertIn("methodology_changes_are_versioned_and_evidence_driven", contract.methodology_rules)
        self.assertIn("operator_can_approve_reject_modify_or_freeze_methodology", contract.methodology_rules)
        self.assertIn("ddos_and_out_of_scope_activity_never_become_methodology_tasks", contract.methodology_rules)
        self.assertIn("markdown_files_are_not_authoritative", contract.markdown_governance)
        self.assertIn("legacy_allowed_markdown_list_superseded_by_active_markdown_removal", contract.markdown_governance)
        self.assertIn("legacy_ai_agent_prd_readonly_rule_superseded_by_typed_migration_and_quarantine", contract.markdown_governance)

    def test_contract_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "assistant_operating_contract.yaml").write_text(
                "id: primordial_assistant_operating_contract\n"
                "source_paths:\n"
                "  - CLAUDE.md\n"
                "status: migrated\n"
                "authority: typed_assistant_guidance_not_runtime_state\n"
                "project_model: []\n"
                "invariants: []\n"
                "operational_priority_order: []\n"
                "layer_order: []\n"
                "layer_map: []\n"
                "execution_model: []\n"
                "validation_commands: []\n"
                "cli_commands: []\n"
                "required_trace_metadata: []\n"
                "tooling_inventory_rules: []\n"
                "resource_budget_rules: []\n"
                "failure_containment_rules: []\n"
                "concurrency_rules: []\n"
                "evidence_progression_rules: []\n"
                "model_routing_rules: []\n"
                "methodology_rules: []\n"
                "markdown_governance: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                AssistantOperatingContractCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
