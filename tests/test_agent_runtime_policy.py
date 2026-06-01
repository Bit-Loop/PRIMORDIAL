from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.core.catalog.agent_runtime_policy import AgentRuntimePolicyCatalog
from primordial.core.catalog.loader import CatalogValidationError


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_DIR = REPO_ROOT / "catalog"


class AgentRuntimePolicyTests(unittest.TestCase):
    def test_agents_markdown_rules_are_migrated_to_policy_catalog(self) -> None:
        policy = AgentRuntimePolicyCatalog(CATALOG_DIR / "policies").load()

        self.assertEqual(policy.id, "primordial_agent_runtime")
        self.assertEqual(policy.default_operator_intent, "recon_only")
        self.assertEqual(
            policy.authority_sources,
            (
                "durable_runtime_state",
                "evidence_records",
                "target_scope",
                "approvals",
                "active_operator_intent",
            ),
        )
        self.assertEqual(policy.boundary_for("chat"), "conversational_context")
        self.assertEqual(policy.boundary_for("per_target_guidance"), "durable_operator_instruction")
        self.assertEqual(policy.boundary_for("operator_intent"), "durable_control_surface")

    def test_profile_label_never_authorizes_restricted_behaviors(self) -> None:
        policy = AgentRuntimePolicyCatalog(CATALOG_DIR / "policies").load()

        for behavior in (
            "public_poc_research",
            "kerberos_attack_checks",
            "credential_validation",
            "lab_flag_collection",
        ):
            self.assertFalse(policy.profile_label_authorizes("hack_the_box", behavior), behavior)

    def test_baseline_autonomy_forbids_unsafe_execution_classes(self) -> None:
        policy = AgentRuntimePolicyCatalog(CATALOG_DIR / "policies").load()

        for behavior in (
            "public_poc_execution",
            "exploit_code_generation",
            "brute_force",
            "credential_spraying",
            "hash_cracking",
            "reverse_shell",
            "shell_true",
            "automatic_tool_installation",
            "unbounded_command_execution",
        ):
            self.assertFalse(policy.baseline_allows(behavior), behavior)

    def test_policy_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "agent_runtime.yaml").write_text(
                "id: bad\n"
                "default_operator_intent: recon_only\n"
                "authority_sources: []\n"
                "boundaries: {}\n"
                "profile_label_denials: []\n"
                "baseline_forbidden_behaviors: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                AgentRuntimePolicyCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
