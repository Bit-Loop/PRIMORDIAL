from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.loader import CatalogValidationError
from primordial.core.catalog.operational_architecture import OperationalArchitectureCatalog


REPO_ROOT = Path(__file__).resolve().parents[1]


class OperationalArchitectureCatalogTests(unittest.TestCase):
    def test_how_primordial_works_markdown_is_migrated_to_typed_architecture_catalog(self) -> None:
        architecture = OperationalArchitectureCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(architecture.id, "primordial_operational_architecture")
        self.assertEqual(architecture.source_path, "docs/HOW_PRIMORDIAL_WORKS.md")
        self.assertEqual(architecture.status, "migrated_operational_model")
        self.assertEqual(architecture.authority, "advisory_operational_model_not_runtime_policy")
        self.assertEqual(architecture.runtime_model, "local_first_deterministic_control_plane")
        self.assertFalse(architecture.always_on_prompt_agent)
        self.assertIn("scope_must_be_explicit", architecture.core_invariants)
        self.assertIn("policy_gates_risky_actions", architecture.core_invariants)
        self.assertIn("tasks_are_durable_records_not_chat_messages", architecture.core_invariants)
        self.assertIn("continuous_mode_is_bounded_repeated_ticks", architecture.core_invariants)

    def test_runtime_assembly_preserves_components_and_facade_boundary(self) -> None:
        architecture = OperationalArchitectureCatalog(REPO_ROOT / "catalog" / "project").load()
        components = {item.name: item for item in architecture.runtime_assembly.components}

        self.assertEqual(architecture.runtime_assembly.entrypoint, "primordial/app/runtime.py")
        self.assertIn("run_tick", architecture.runtime_assembly.facade_methods)
        self.assertIn("register_target", architecture.runtime_assembly.facade_methods)
        self.assertIn("ask_operator_ai", architecture.runtime_assembly.facade_methods)
        self.assertIn("credential_setters", architecture.runtime_assembly.facade_methods)
        self.assertEqual(components["RuntimeStore"].role, "postgres_pgvector_backed_durable_operational_state")
        self.assertEqual(components["WorkflowOrchestrator"].role, "plans_and_executes_bounded_task_ticks")
        self.assertEqual(components["PolicyEngine"].role, "decides_allowed_denied_or_needs_approval")
        self.assertEqual(components["ModuleRegistry"].role, "lazy_loads_security_notion_discord_and_caido_modules")
        self.assertIn("ui_and_cli_layers_prefer_runtime_facade_methods", architecture.runtime_assembly.boundaries)

    def test_storage_scope_tick_and_planning_model_are_machine_readable(self) -> None:
        architecture = OperationalArchitectureCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(architecture.storage.source_of_truth, "postgres_pgvector_runtime_store")
        self.assertIn("PRIMORDIAL_DATABASE_URL", architecture.storage.required_environment)
        self.assertIn("targets", architecture.storage.records)
        self.assertIn("policy_decisions", architecture.storage.records)
        self.assertIn("ui_panels_notion_exports_chat_logs_and_markdown_guidance_are_derived_or_auxiliary", architecture.storage.boundaries)

        self.assertIn("PrimordialRuntime.register_target", architecture.scope_and_targets.entrypoints)
        self.assertIn("PrimordialRuntime.import_scope_payload", architecture.scope_and_targets.entrypoints)
        self.assertIn("workflow_planner_needs_targets_and_assets_before_useful_work", architecture.scope_and_targets.rules)

        self.assertEqual(
            architecture.execution_model.tick_pipeline,
            (
                "operator_ui_or_continuous_loop",
                "PrimordialRuntime.run_tick",
                "WorkflowOrchestrator.tick",
            ),
        )
        self.assertEqual(
            architecture.execution_model.tick_steps,
            (
                "resume_due_waiting_tasks",
                "inspect_targets",
                "plan_missing_methodology_tasks",
                "run_behavior_verifier_checks",
                "execute_ready_tasks_up_to_max_executions",
                "process_external_queues",
            ),
        )
        self.assertIn("if_no_evidence_plan_recon", architecture.workflow_planning.rules)
        self.assertIn("avoid_repeating_completed_work_unless_evidence_changes_or_retry_resume_rule_applies", architecture.workflow_planning.rules)

    def test_policy_primitives_ai_and_interface_boundaries_are_preserved(self) -> None:
        architecture = OperationalArchitectureCatalog(REPO_ROOT / "catalog" / "project").load()
        ai_roles = {item.id: item for item in architecture.ai_model_use.roles}
        interfaces = {item.id: item for item in architecture.interfaces}

        self.assertIn("scope", architecture.policy_and_safety.evaluates_against)
        self.assertIn("agent_safety_approval_metadata", architecture.policy_and_safety.evaluates_against)
        self.assertIn("ai_suggestion_is_not_sufficient_for_risky_exploitation_or_poc_execution", architecture.policy_and_safety.rules)
        self.assertIn("manifests/*.json", architecture.workers_and_primitives.manifest_paths)
        self.assertIn("model_reasons_over_capability_and_metadata_not_arbitrary_shell_commands", architecture.workers_and_primitives.rules)
        self.assertIn("normalized_evidence", architecture.workers_and_primitives.outputs)

        self.assertEqual(ai_roles["local_fast"].purpose, "hot_path_orchestration_and_broad_analysis")
        self.assertEqual(ai_roles["local_code"].purpose, "mission_critical_code_exploit_research_and_poc_adaptation")
        self.assertIn("persistent_knowledge_stored_as_structured_records_and_per_target_guidance", architecture.ai_model_use.boundaries)

        self.assertIn("automation", interfaces["cli"].uses)
        self.assertIn("do_not_implement_separate_business_logic", interfaces["cli"].rules)
        self.assertIn("do_not_update_tk_widgets_directly_from_background_threads", interfaces["gui"].rules)
        self.assertIn("local_no_auth_no_multi_user_no_server_sent_updates", interfaces["web_app"].rules)

    def test_auxiliary_views_sync_flow_strengths_weak_points_and_safe_rules_are_preserved(self) -> None:
        architecture = OperationalArchitectureCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertIn("notion_exports_are_external_views_not_source_of_truth", architecture.auxiliary_views.rules)
        self.assertIn("discord_is_not_an_audit_log", architecture.auxiliary_views.rules)
        self.assertIn("findings_guidance_is_bounded_per_target_context_not_raw_scanner_dump", architecture.auxiliary_views.rules)
        self.assertIn("guidance_markdown_is_runtime_auxiliary_not_repo_source_truth", architecture.auxiliary_views.rules)

        self.assertEqual(
            architecture.critical_data_flow,
            (
                "operator_imports_target",
                "runtime_registers_target_and_assets",
                "tick_plans_recon_or_service_tasks",
                "policy_validates_task",
                "provider_router_chooses_model_route",
                "worker_executes_primitive",
                "evidence_artifacts_notes_interests_written",
                "memory_guidance_export_notification_queues_update",
                "gui_web_cli_render_refreshed_state",
            ),
        )
        self.assertIn("bounded_tick_architecture_safer_than_persistent_autonomous_prompt", architecture.current_strengths)
        self.assertIn("primordial_runtime_is_becoming_god_object", architecture.current_weak_points)
        self.assertIn("v1_runtime_storage_is_postgres_pgvector_only_sqlite_is_historical", architecture.current_weak_points)
        self.assertIn("do_not_bypass_policy_engine_for_risky_work", architecture.safe_development_rules)
        self.assertIn("do_not_expose_arbitrary_shell_execution_to_ai_workers", architecture.safe_development_rules)

    def test_operational_architecture_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "operational_architecture.yaml").write_text(
                "id: primordial_operational_architecture\n"
                "source_path: docs/HOW_PRIMORDIAL_WORKS.md\n"
                "status: migrated_operational_model\n"
                "authority: advisory_operational_model_not_runtime_policy\n"
                "runtime_model: local_first_deterministic_control_plane\n"
                "always_on_prompt_agent: false\n"
                "core_invariants: []\n"
                "runtime_assembly:\n"
                "  entrypoint: primordial/app/runtime.py\n"
                "  components: []\n"
                "  facade_methods: []\n"
                "  boundaries: []\n"
                "storage:\n"
                "  files: []\n"
                "  source_of_truth: postgres_pgvector_runtime_store\n"
                "  required_environment: []\n"
                "  records: []\n"
                "  boundaries: []\n"
                "scope_and_targets:\n"
                "  entrypoints: []\n"
                "  target_fields: []\n"
                "  input_surfaces: []\n"
                "  rules: []\n"
                "execution_model:\n"
                "  tick_pipeline: []\n"
                "  tick_steps: []\n"
                "  modes: []\n"
                "workflow_planning:\n"
                "  files: []\n"
                "  rules: []\n"
                "policy_and_safety:\n"
                "  file: primordial/core/orchestration/policy.py\n"
                "  evaluates_against: []\n"
                "  rules: []\n"
                "workers_and_primitives:\n"
                "  files: []\n"
                "  task_handlers: []\n"
                "  manifest_paths: []\n"
                "  outputs: []\n"
                "  rules: []\n"
                "ai_model_use:\n"
                "  files: []\n"
                "  roles: []\n"
                "  uses: []\n"
                "  boundaries: []\n"
                "operator_chat_and_ai_thinking:\n"
                "  entrypoints: []\n"
                "  storage: []\n"
                "  display_rules: []\n"
                "auxiliary_views:\n"
                "  findings_paths: []\n"
                "  integration_files: []\n"
                "  rules: []\n"
                "interfaces: []\n"
                "ui_sync:\n"
                "  shared_store_items: []\n"
                "  rules: []\n"
                "critical_data_flow: []\n"
                "current_strengths: []\n"
                "current_weak_points: []\n"
                "safe_development_rules: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                OperationalArchitectureCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
