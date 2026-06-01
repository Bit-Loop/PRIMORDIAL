from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.loader import CatalogValidationError
from primordial.core.catalog.v2_reverse_engineering_test_plan import V2ReverseEngineeringTestPlanCatalog


REPO_ROOT = Path(__file__).resolve().parents[1]


class V2ReverseEngineeringTestPlanCatalogTests(unittest.TestCase):
    def test_test_plan_markdown_is_migrated_to_non_runtime_typed_catalog(self) -> None:
        plan = V2ReverseEngineeringTestPlanCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(plan.id, "primordial_v2_reverse_engineering_test_plan")
        self.assertEqual(plan.source_path, "docs/v2/reverse_engineering_test_plan.md")
        self.assertEqual(plan.status, "v2_preparation_only")
        self.assertFalse(plan.loaded_by_v1_runtime)
        self.assertEqual(plan.authority, "typed_v2_acceptance_plan_not_v1_runtime_authority")
        self.assertIn("fixture_driven", plan.test_philosophy)
        self.assertIn("deterministic_where_possible", plan.test_philosophy)
        self.assertIn("hardware_risk_explicit", plan.test_philosophy)
        self.assertIn("no_live_uncontrolled_targets", plan.test_philosophy)
        self.assertIn("no_hidden_model_behavior_dependency", plan.test_philosophy)

    def test_acceptance_gates_and_fixture_requirements_are_explicit(self) -> None:
        plan = V2ReverseEngineeringTestPlanCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(
            plan.fixture_requirements,
            (
                "provenance",
                "authorization_class",
                "expected_artifact_hashes",
                "expected_tool_outputs",
                "expected_policy_verdicts",
            ),
        )
        self.assertIn(
            "runner_requires_subject_authorization_tool_manifest_timeout_and_artifact_directory",
            plan.acceptance_gates,
        )
        self.assertIn("static_analysis_tests_pass_without_hardware_access", plan.acceptance_gates)
        self.assertIn("dynamic_binary_tests_run_only_against_local_fixture_binaries_and_harnesses", plan.acceptance_gates)
        self.assertIn("active_hardware_flash_fuse_glitch_or_invasive_operations_blocked_by_default", plan.acceptance_gates)
        self.assertIn("ai_suggestions_remain_proposals_until_deterministic_policy_accepts_operation", plan.acceptance_gates)
        self.assertIn("large_outputs_stored_as_hash_referenced_artifacts_not_inlined_logs", plan.acceptance_gates)
        self.assertIn("unsafe_approval_request", plan.failure_modes)

    def test_fixture_corpus_preserves_expected_checks(self) -> None:
        plan = V2ReverseEngineeringTestPlanCatalog(REPO_ROOT / "catalog" / "project").load()
        corpora = {corpus.id: corpus for corpus in plan.fixture_corpus}

        self.assertIn("elf_x86_64_parser_stack_overflow_local_harness", corpora["binary_fixtures"].fixtures)
        self.assertIn("arm32_little_endian_firmware_utility_binary", corpora["binary_fixtures"].fixtures)
        self.assertIn("no_reverse_shells_credential_theft_or_public_target_instructions", corpora["binary_fixtures"].expected_checks)
        self.assertIn("signed_update_package_extraction_allowed_signature_bypass_blocked", corpora["firmware_fixtures"].fixtures)
        self.assertIn("secret_values_redacted_from_summaries", corpora["firmware_fixtures"].expected_checks)
        self.assertIn("swd_jtag_idcode_scan_transcript", corpora["hardware_capture_fixtures"].fixtures)
        self.assertIn("active_probing_blocked_without_hardware_active_intent_and_approval", corpora["hardware_capture_fixtures"].expected_checks)
        self.assertIn("encrypted_or_unsupported_bitstream_classifies_non_decodable", corpora["fpga_fixtures"].fixtures)
        self.assertIn("no_encryption_or_device_bound_protection_bypass", corpora["fpga_fixtures"].expected_checks)

    def test_policy_safety_runner_bench_and_release_criteria_are_typed(self) -> None:
        plan = V2ReverseEngineeringTestPlanCatalog(REPO_ROOT / "catalog" / "project").load()
        intent_tests = {test.intent_id: test for test in plan.policy_tests.intent_gate_tests}

        self.assertIn("blocks_dynamic_execution", intent_tests["reverse_engineering_observe"].blocks)
        self.assertIn("blocks_weaponized_payload_generation", intent_tests["binary_exploitability_assessment"].blocks)
        self.assertIn("blocks_flash_write_fuse_glitch_operations", intent_tests["hardware_probe_active"].blocks)
        self.assertIn("blocks_encrypted_bitstream_bypass_attempts", intent_tests["fpga_netlist_analysis"].blocks)
        self.assertIn("prompted_exploit_generation_returns_blocked_proposal", plan.policy_tests.safety_regression_tests)
        self.assertIn("public_ip_or_third_party_domain_in_strings_not_execution_target", plan.policy_tests.safety_regression_tests)
        self.assertIn("missing_executable_returns_tool_unavailable", plan.tool_runner_tests.baseline_contract)
        self.assertIn("command_argv_recorded_without_shell_string", plan.tool_runner_tests.baseline_contract)
        self.assertIn("firmware_bom_runner", plan.tool_runner_tests.required_runner_suites)
        self.assertIn("verilog_simulation_runner", plan.tool_runner_tests.required_runner_suites)
        self.assertIn("voltage_domain_measurements", plan.hardware_bench_qualification)
        self.assertIn("operator_confirmation_for_exact_operation_class", plan.hardware_bench_qualification)
        self.assertIn("fixture_corpus_committed_without_proprietary_or_secret_material", plan.release_criteria)

    def test_test_plan_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "v2_reverse_engineering_test_plan.yaml").write_text(
                "id: primordial_v2_reverse_engineering_test_plan\n"
                "source_path: docs/v2/reverse_engineering_test_plan.md\n"
                "status: v2_preparation_only\n"
                "loaded_by_v1_runtime: false\n"
                "authority: typed_v2_acceptance_plan_not_v1_runtime_authority\n"
                "test_philosophy: []\n"
                "fixture_requirements: []\n"
                "acceptance_gates: []\n"
                "failure_modes: []\n"
                "fixture_corpus: []\n"
                "policy_tests:\n"
                "  intent_gate_tests: []\n"
                "  safety_regression_tests: []\n"
                "tool_runner_tests:\n"
                "  baseline_contract: []\n"
                "  required_runner_suites: []\n"
                "hardware_bench_qualification: []\n"
                "release_criteria: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                V2ReverseEngineeringTestPlanCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
