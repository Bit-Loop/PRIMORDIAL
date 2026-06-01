from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.loader import CatalogValidationError
from primordial.core.catalog.v2_reverse_engineering_framework import V2ReverseEngineeringFrameworkCatalog


REPO_ROOT = Path(__file__).resolve().parents[1]


class V2ReverseEngineeringFrameworkCatalogTests(unittest.TestCase):
    def test_framework_markdown_is_migrated_to_non_runtime_typed_catalog(self) -> None:
        framework = V2ReverseEngineeringFrameworkCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(framework.id, "primordial_v2_reverse_engineering_framework")
        self.assertEqual(framework.source_path, "docs/v2/reverse_engineering_framework.md")
        self.assertEqual(framework.status, "v2_preparation_only")
        self.assertFalse(framework.loaded_by_v1_runtime)
        self.assertEqual(framework.authority, "typed_v2_planning_not_v1_runtime_authority")
        self.assertIn(
            "scope_evidence_approvals_operator_intent_artifacts_and_tool_provenance_are_authority",
            framework.purpose,
        )
        self.assertIn("v1_runtime_integration_deferred", framework.design_boundaries)
        self.assertIn(
            "shell_false_argv_only_timeout_bounded_workspace_isolated_provenance_recorded",
            framework.design_boundaries,
        )
        self.assertIn("weaponized_payload_generation_out_of_baseline_scope", framework.design_boundaries)

    def test_work_domains_preserve_questions_and_required_artifacts(self) -> None:
        framework = V2ReverseEngineeringFrameworkCatalog(REPO_ROOT / "catalog" / "project").load()
        domains = {domain.id: domain for domain in framework.work_domains}

        self.assertEqual(
            set(domains),
            {
                "binary_exploitation_research",
                "software_reverse_engineering",
                "embedded_and_firmware_reverse_engineering",
                "hardware_and_fpga_reverse_engineering",
            },
        )
        self.assertIn(
            "architecture_abi_format_compiler_hardening_dependency_surface",
            domains["binary_exploitation_research"].primary_questions,
        )
        self.assertIn(
            "binary_identity_hash_format_architecture_bitness_endian_compiler_libraries",
            domains["binary_exploitation_research"].required_artifacts,
        )
        self.assertIn(
            "trust_boundary_map_with_evidence_references",
            domains["software_reverse_engineering"].required_artifacts,
        )
        self.assertIn(
            "firmware_bill_of_materials_hashes_partitions_filesystems_init_services_credential_indicators",
            domains["embedded_and_firmware_reverse_engineering"].required_artifacts,
        )
        self.assertIn(
            "board_inventory_power_tree_clock_tree_io_voltage_map_connector_map",
            domains["hardware_and_fpga_reverse_engineering"].required_artifacts,
        )

    def test_control_plane_intent_gates_default_posture_and_workflows_are_explicit(self) -> None:
        framework = V2ReverseEngineeringFrameworkCatalog(REPO_ROOT / "catalog" / "project").load()
        gates = {gate.id: gate for gate in framework.intent_gates}
        workflows = {workflow.id: workflow for workflow in framework.workflow_families}

        self.assertIn("subject", framework.control_plane_records)
        self.assertIn("authorization", framework.control_plane_records)
        self.assertIn("artifact", framework.control_plane_records)
        self.assertIn("hazard", framework.control_plane_records)
        self.assertIn("static_analysis_metadata_extraction_read_only_classification", gates["reverse_engineering_observe"].allows)
        self.assertIn("emulator_or_local_harness_execution_against_owned_artifacts", gates["reverse_engineering_dynamic"].allows)
        self.assertIn("flash_erase_write_fuse_changes_glitching_invasive_work_decap_irreversible_actions", gates["hardware_destructive"].allows)
        self.assertIn("static_analysis_before_dynamic_execution", framework.default_posture)
        self.assertIn("emulation_before_physical_hardware_interaction", framework.default_posture)
        self.assertIn("active_hardware_blocked_until_identity_limits_connection_and_recovery_plan_exist", framework.default_posture)
        self.assertIn("firmware_bom_services_ports_scripts_endpoints_certificates_secret_indicators", workflows["firmware_intake"].steps)
        self.assertIn("voltage_domains_measured_before_digital_instrument_connection", workflows["board_intake"].steps)

    def test_evidence_ai_limits_milestones_and_reference_anchors_are_typed(self) -> None:
        framework = V2ReverseEngineeringFrameworkCatalog(REPO_ROOT / "catalog" / "project").load()
        sensitivities = {item.id: item.description for item in framework.evidence_standards.sensitivity_classes}
        anchors = {anchor.label: anchor.url for anchor in framework.official_reference_anchors}

        self.assertIn("argv", framework.evidence_standards.required_fields)
        self.assertIn("operator_intent_id", framework.evidence_standards.required_fields)
        self.assertIn("authorization_ref", framework.evidence_standards.required_fields)
        self.assertIn("secrets_possible", sensitivities)
        self.assertIn("device_damage_risk", sensitivities)
        self.assertIn("weaponized_exploit_payloads", framework.ai_control_plane.blocked_baseline_outputs)
        self.assertIn("reverse_shells_credential_theft_persistence_or_evasion", framework.ai_control_plane.blocked_baseline_outputs)
        self.assertIn("crash_classification_and_missing_precondition_analysis", framework.ai_control_plane.allowed_outputs)
        self.assertEqual(framework.implementation_milestones[0], "static_artifact_and_subject_model")
        self.assertIn("policy_test_suite_and_fixture_corpus", framework.implementation_milestones)
        self.assertEqual(anchors["Ghidra official repository"], "https://github.com/NationalSecurityAgency/ghidra")
        self.assertEqual(anchors["Yosys documentation"], "https://yosyshq.readthedocs.io/projects/yosys/")

    def test_framework_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "v2_reverse_engineering_framework.yaml").write_text(
                "id: primordial_v2_reverse_engineering_framework\n"
                "source_path: docs/v2/reverse_engineering_framework.md\n"
                "status: v2_preparation_only\n"
                "loaded_by_v1_runtime: false\n"
                "authority: typed_v2_planning_not_v1_runtime_authority\n"
                "purpose: []\n"
                "design_boundaries: []\n"
                "work_domains: []\n"
                "control_plane_records: []\n"
                "intent_gates: []\n"
                "default_posture: []\n"
                "workflow_families: []\n"
                "evidence_standards:\n"
                "  required_fields: []\n"
                "  sensitivity_classes: []\n"
                "ai_control_plane:\n"
                "  allowed_outputs: []\n"
                "  blocked_baseline_outputs: []\n"
                "implementation_milestones: []\n"
                "official_reference_anchors: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                V2ReverseEngineeringFrameworkCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
