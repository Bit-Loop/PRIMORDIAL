from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.loader import CatalogValidationError
from primordial.core.catalog.model_selection import ModelSelectionCatalog
from primordial.core.providers.wrapper_prompts import WRAPPER_ROLE_PERSONALITY_PROMPTS


REPO_ROOT = Path(__file__).resolve().parents[1]


class ModelSelectionCatalogTests(unittest.TestCase):
    def test_model_selection_markdown_is_migrated_to_typed_catalog(self) -> None:
        selection = ModelSelectionCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(selection.id, "primordial_model_selection_20260509")
        self.assertEqual(selection.source_path, "docs/MODEL_SELECTION_NOTES.md")
        self.assertEqual(selection.status, "migrated_benchmark_guidance")
        self.assertEqual(selection.authority, "recommendation_catalog_not_runtime_mutation")
        self.assertEqual(selection.date, "2026-05-09")
        self.assertIn("codex_primordial_model_role_benchmark_20260509.md", selection.evidence_sources)
        self.assertIn("codex_primordial_OLLAMA-model_role_benchmark_20260509.md", selection.evidence_sources)

    def test_role_selection_preserves_current_and_target_models_without_auto_mutation(self) -> None:
        selection = ModelSelectionCatalog(REPO_ROOT / "catalog" / "project").load()
        roles = {item.role: item for item in selection.role_selection}

        self.assertEqual(roles["local_fast"].best_current_models, ("gemma4:e4b",))
        self.assertEqual(roles["local_fast"].optimal_targets, ("gemma4:e4b",))
        self.assertIn("deterministic_policy_checks", roles["local_fast"].decision)
        self.assertEqual(roles["local_deep"].best_current_models, ())
        self.assertEqual(roles["local_deep"].optimal_targets, ("gpt-oss-safeguard-20b",))
        self.assertIn("current_local_models_failed_durable_authority_reasoning", roles["local_deep"].decision)
        self.assertEqual(roles["local_code"].best_current_models, ("gemma4:e4b",))
        self.assertIn("qwen3-coder-next:q4_K_M", roles["local_code"].optimal_targets)
        self.assertIn("deterministic_policy_checks", roles["poc_pressure"].optimal_targets)
        self.assertEqual(roles["rag_embeddings"].best_current_models, ("text-embedding-nomic-embed-text-v1.5",))
        self.assertIn("source_id_validation", roles["rag_synthesis"].decision)

    def test_local_deep_failure_pattern_preserves_authority_hierarchy_and_guardrails(self) -> None:
        selection = ModelSelectionCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(
            selection.local_deep.authority_hierarchy,
            (
                "durable_operator_intent",
                "durable_approvals",
                "target_scope",
                "evidence_records",
                "durable_guidance",
                "chat_request",
            ),
        )
        self.assertIn("chat_guidance_overrode_recon_only", selection.local_deep.observed_failures)
        self.assertIn("read_only_recon_approval_overrode_credential_validation_block", selection.local_deep.observed_failures)
        self.assertIn("gpt_oss_safeguard_20b_matches_policy_reasoning_classifier_need", selection.local_deep.target_rationale)
        self.assertIn("models_must_not_directly_expand_target_scope", selection.operating_guardrails)
        self.assertIn("chat_requests_must_not_override_durable_operator_intent", selection.operating_guardrails)
        self.assertIn("route_uncertain_local_deep_to_supervised_or_offloaded_review", selection.operating_guardrails)

    def test_wrapper_only_mode_preserves_personalities_and_authority_boundary(self) -> None:
        selection = ModelSelectionCatalog(REPO_ROOT / "catalog" / "project").load()
        personalities = {item.role: item for item in selection.wrapper_only_mode.personalities}

        self.assertIn("PRIMORDIAL_USE_ONLY_WRAPPER_MODE=1", selection.wrapper_only_mode.activation_settings)
        self.assertIn("persisted_model_wrapper_setting_enabled", selection.wrapper_only_mode.activation_settings)
        self.assertIn("ollama_startup_topology_validation", selection.wrapper_only_mode.bypassed_actions)
        self.assertIn("model_warmup", selection.wrapper_only_mode.bypassed_actions)
        self.assertEqual(
            selection.wrapper_only_mode.authority_boundary,
            "wrapper_prompts_do_not_grant_authority_control_plane_remains_operator_intent_approvals_scope_evidence_validators",
        )
        self.assertEqual(set(personalities), set(WRAPPER_ROLE_PERSONALITY_PROMPTS))
        self.assertEqual(personalities["local_deep"].personality, "policy_and_authority_arbiter")
        self.assertEqual(personalities["poc_pressure"].personality, "poc_boundary_reviewer")
        self.assertEqual(personalities["rag_synthesis"].personality, "citation_bound_synthesis")

    def test_gate_pipeline_handoff_and_validator_rules_are_structured(self) -> None:
        selection = ModelSelectionCatalog(REPO_ROOT / "catalog" / "project").load()
        channels = {item.channel: item for item in selection.agent_communication.durable_channels}

        self.assertEqual(
            selection.authority_pipeline.steps,
            (
                "deterministic_policy_pre_checks",
                "policy_model_classification",
                "general_reasoning_model_for_explanation_only",
                "deterministic_post_checks_before_durable_state_mutation",
            ),
        )
        self.assertEqual(selection.poc_pressure_split.design_surface, "poc_design")
        self.assertEqual(selection.poc_pressure_split.execution_gate, "poc_execution_gate")
        self.assertEqual(selection.agent_communication.core_rule, "models_recommend_classify_summarize_and_draft_runtime_grants_authority")
        self.assertEqual(channels["approval_records"].used_by, ("policy_gate", "local_deep", "poc_execution_gate"))
        self.assertIn("operator_intent", selection.agent_communication.canonical_handoff_packet_fields)
        self.assertIn("required_output", selection.agent_communication.canonical_handoff_packet_fields)
        self.assertIn("decision", selection.agent_communication.accepted_gate_response_fields)
        self.assertIn("controlling_authority", selection.agent_communication.accepted_gate_response_fields)
        self.assertIn("reject_missing_operator_intent", selection.agent_communication.validator_rejection_rules)
        self.assertIn("reject_poc_execution_approval_from_non_policy_model", selection.agent_communication.validator_rejection_rules)

    def test_next_tests_and_followups_preserve_hard_pass_conditions(self) -> None:
        selection = ModelSelectionCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertIn("install_or_expose_gpt_oss_safeguard_20b_locally", selection.next_tests)
        self.assertIn("require_allowed_blocked_missing_authority_controlling_authority_and_exact_ids", selection.next_tests)
        self.assertIn(
            "credential_validation_must_remain_blocked_under_recon_only_without_durable_intent_and_approval",
            selection.next_tests,
        )
        self.assertIn("create_regression_benchmark_with_exact_hard_cases", selection.follow_up_changes)
        self.assertIn("require_every_gate_output_to_cite_controlling_authority_id", selection.follow_up_changes)
        self.assertIn("gemma4_e4b_for_quick_operator_ux_never_final_approval_authority", selection.follow_up_changes)

    def test_model_selection_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "model_selection.yaml").write_text(
                "id: primordial_model_selection_20260509\n"
                "source_path: docs/MODEL_SELECTION_NOTES.md\n"
                "status: migrated_benchmark_guidance\n"
                "authority: recommendation_catalog_not_runtime_mutation\n"
                "date: '2026-05-09'\n"
                "purpose: []\n"
                "evidence_sources: []\n"
                "role_selection: []\n"
                "local_deep:\n"
                "  authority_hierarchy: []\n"
                "  observed_failures: []\n"
                "  target_model: gpt-oss-safeguard-20b\n"
                "  target_rationale: []\n"
                "operating_guardrails: []\n"
                "practical_configuration: []\n"
                "wrapper_only_mode:\n"
                "  activation_settings: []\n"
                "  applies_to: []\n"
                "  bypassed_actions: []\n"
                "  authority_boundary: boundary\n"
                "  personalities: []\n"
                "next_tests: []\n"
                "external_model_notes:\n"
                "  escalation_order: []\n"
                "  rules: []\n"
                "  reference_links: []\n"
                "authority_pipeline:\n"
                "  steps: []\n"
                "poc_pressure_split:\n"
                "  design_surface: poc_design\n"
                "  execution_gate: poc_execution_gate\n"
                "  rules: []\n"
                "follow_up_changes: []\n"
                "agent_communication:\n"
                "  core_rule: core\n"
                "  flow: []\n"
                "  durable_channels: []\n"
                "  handoff_sequence: []\n"
                "  canonical_handoff_packet_fields: []\n"
                "  accepted_gate_response_fields: []\n"
                "  validator_rejection_rules: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                ModelSelectionCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
