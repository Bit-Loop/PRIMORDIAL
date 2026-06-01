from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.codebase_floor_plan import CodebaseFloorPlanCatalog
from primordial.core.catalog.loader import CatalogValidationError


REPO_ROOT = Path(__file__).resolve().parents[1]


class CodebaseFloorPlanCatalogTests(unittest.TestCase):
    def test_floor_plan_markdown_is_migrated_to_typed_editing_map(self) -> None:
        floor_plan = CodebaseFloorPlanCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(floor_plan.id, "primordial_codebase_floor_plan")
        self.assertEqual(floor_plan.source_path, "docs/FLOOR_PLAN.md")
        self.assertEqual(floor_plan.status, "migrated_editing_map")
        self.assertEqual(floor_plan.authority, "advisory_editing_map_not_runtime_policy")
        self.assertIn("where_features_live", floor_plan.purpose)
        self.assertIn("what_files_change_together", floor_plan.purpose)

    def test_top_level_layout_preserves_runtime_and_data_boundaries(self) -> None:
        floor_plan = CodebaseFloorPlanCatalog(REPO_ROOT / "catalog" / "project").load()
        areas = {item.path: item for item in floor_plan.top_level_layout}

        self.assertEqual(areas["primordial/cli.py"].role, "main_command_line_interface")
        self.assertIn("add_commands_only_after_runtime_exposes_behavior", areas["primordial/cli.py"].guidance)
        self.assertEqual(areas["primordial/app/runtime.py"].role, "application_composition_root_and_service_facade")
        self.assertIn("ui_cli_and_web_actions_call_runtime_methods", areas["primordial/app/runtime.py"].guidance)
        self.assertIn("treat_carefully_large_file", areas["primordial/app/runtime.py"].guidance)
        self.assertEqual(areas["findings/"].role, "durable_operator_facing_findings_workspace")
        self.assertIn("runtime_data_not_core_source_code", areas["findings/"].guidance)
        self.assertEqual(areas["runtime/"].role, "sqlite_crash_journal_and_runtime_state")
        self.assertIn("do_not_manually_edit_without_debugging_backups", areas["runtime/"].guidance)
        self.assertEqual(areas["primordial/n8n-master/"].role, "reference_vendor_material")
        self.assertIn("avoid_broad_searches_unless_comparing_against_n8n", areas["primordial/n8n-master/"].guidance)

    def test_common_edit_paths_preserve_ordered_runtime_web_gui_and_tool_rules(self) -> None:
        floor_plan = CodebaseFloorPlanCatalog(REPO_ROOT / "catalog" / "project").load()
        paths = {item.id: item for item in floor_plan.common_edit_paths}

        runtime_feature = paths["add_runtime_feature"]
        self.assertEqual(
            runtime_feature.ordered_steps,
            (
                "add_domain_types_if_needed",
                "add_durable_persistence_if_needed",
                "add_facade_methods_in_primordial_runtime",
                "expose_through_cli_if_useful",
                "expose_through_web_if_operator_facing",
                "expose_through_gui_if_operator_facing",
                "add_tests_under_tests",
            ),
        )
        self.assertIn("ui_layers_should_call_primordial_runtime_not_storage_internals", runtime_feature.rules)

        web_control = paths["add_web_console_control"]
        self.assertIn("primordial/core/web/app.py", web_control.files)
        self.assertIn("primordial/core/web/static/app.js", web_control.files)
        self.assertIn("tests/test_web_console.py", web_control.files)
        self.assertIn("business_logic_stays_in_primordial_runtime", web_control.rules)

        gui_control = paths["add_gui_control"]
        self.assertIn("use_run_background_for_model_storage_network_tool_or_filesystem_work", gui_control.rules)
        self.assertIn("do_not_update_tk_widgets_directly_from_background_threads", gui_control.rules)

        primitive = paths["add_primitive_or_tool"]
        self.assertIn("models_reason_about_capability_not_raw_shell_chaos", primitive.rules)
        self.assertIn("dos_flooding_destructive_behavior_and_unbounded_bruteforce_stay_blocked", primitive.rules)

    def test_current_ui_areas_and_test_map_are_machine_readable(self) -> None:
        floor_plan = CodebaseFloorPlanCatalog(REPO_ROOT / "catalog" / "project").load()
        ui = {item.id: item for item in floor_plan.current_ui_edit_areas}
        tests = {item.path: item for item in floor_plan.test_map}

        self.assertEqual(ui["local_gui"].files, ("primordial/gui/launcher.py",))
        self.assertIn("main_web_server_controls_target_scope_guidance_workflow_output", ui["local_gui"].areas)
        self.assertIn("agent_monitor_traces_task_runs_worker_ai_notes", ui["local_gui"].areas)
        self.assertIn("file_too_large_split_into_smaller_view_controller_modules", ui["local_gui"].known_issues)

        self.assertIn("primordial/core/web/static/index.html", ui["web_app"].files)
        self.assertIn("operator_ai", ui["web_app"].areas)
        self.assertIn("audit_records", ui["web_app"].areas)
        self.assertIn("app_js_should_split_by_domain", ui["web_app"].known_issues)

        self.assertIn("web_endpoints", tests["tests/test_web_console.py"].coverage)
        self.assertIn("recon_searchsploit_ad_kerberos_credentialed_access", tests["tests/test_runtime_integration.py"].coverage)
        self.assertIn("planning_and_workflow_transitions", tests["tests/test_workflow.py"].coverage)
        self.assertIn("secret_storage_and_redaction", tests["tests/test_credentials.py"].coverage)

    def test_refactor_priorities_preserve_order(self) -> None:
        floor_plan = CodebaseFloorPlanCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(
            floor_plan.refactor_priorities,
            (
                "split_primordial_gui_launcher_into_tab_modules",
                "split_web_static_app_js_into_focused_modules",
                "split_security_execution_into_primitive_handler_families",
                "move_repetitive_api_action_response_wiring_into_helpers_or_router_table",
                "add_explicit_schema_version_migrations_for_storage",
                "add_richer_server_side_continuous_mode_if_browser_ticks_unreliable",
                "add_stronger_typed_api_contract_for_web_gui_payloads",
            ),
        )

    def test_codebase_floor_plan_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "codebase_floor_plan.yaml").write_text(
                "id: primordial_codebase_floor_plan\n"
                "source_path: docs/FLOOR_PLAN.md\n"
                "status: migrated_editing_map\n"
                "authority: advisory_editing_map_not_runtime_policy\n"
                "purpose: []\n"
                "top_level_layout: []\n"
                "common_edit_paths: []\n"
                "current_ui_edit_areas: []\n"
                "test_map: []\n"
                "refactor_priorities: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                CodebaseFloorPlanCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
