from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from primordial.core.autonomy import MethodologyCompiler, ScriptSafetyValidator, ToolInventory, ToolingGap, ToolingGapResolver
from primordial.core.catalog.loader import CatalogValidationError
from primordial.core.catalog.structured_autonomy import StructuredAutonomyCatalog
from primordial.core.intent import OperatorIntentRegistry


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_DIR = REPO_ROOT / "catalog"


class StructuredAutonomyCatalogTests(unittest.TestCase):
    def test_structured_autonomy_markdown_is_migrated_to_typed_catalog(self) -> None:
        autonomy = StructuredAutonomyCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(autonomy.id, "primordial_structured_autonomy")
        self.assertEqual(autonomy.source_path, "docs/structured_autonomy.md")
        self.assertEqual(autonomy.status, "migrated_autonomy_scaffold")
        self.assertEqual(autonomy.authority, "typed_scaffold_description_not_policy_authority")
        self.assertIn("tool_inventory", autonomy.scaffold_support)
        self.assertIn("missing_tool_resolution", autonomy.scaffold_support)
        self.assertIn("failure_diagnosis", autonomy.scaffold_support)
        self.assertIn("script_safety_validation", autonomy.scaffold_support)
        self.assertIn("methodology_proposals", autonomy.scaffold_support)

    def test_tool_inventory_checks_and_safe_substitution_match_runtime_behavior(self) -> None:
        autonomy = StructuredAutonomyCatalog(REPO_ROOT / "catalog" / "project").load()
        inventory = {item.id: item for item in autonomy.tool_inventory_checks}
        substitutions = {item.capability: item for item in autonomy.tooling_gap_substitutions}

        self.assertEqual(inventory["approved_executables"].mechanism, "shutil.which")
        self.assertEqual(inventory["approved_python_packages"].mechanism, "importlib.metadata")
        self.assertEqual(inventory["trusted_scripts"].mechanism, "configured_path_exists")
        self.assertEqual(substitutions["smb_share_enumeration"].preferred_tool, "netexec")
        self.assertEqual(substitutions["smb_share_enumeration"].substitute_tool, "smbclient")
        self.assertIn("read_only_smb_share_enumeration", substitutions["smb_share_enumeration"].rationale)

        registry = OperatorIntentRegistry(CATALOG_DIR / "intents")
        registry.load()
        with patch("shutil.which", side_effect=lambda name: f"/usr/bin/{name}" if name == "smbclient" else None):
            outcome = ToolingGapResolver(ToolInventory(approved_executables=["smbclient"])).resolve(
                ToolingGap("smb_share_enumeration", "netexec", "missing"),
                registry.get("recon_only").policy,
            )
        self.assertEqual(outcome.substitute_tool, "smbclient")  # type: ignore[union-attr]

    def test_failure_diagnosis_and_script_safety_rules_are_explicit(self) -> None:
        autonomy = StructuredAutonomyCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertIn("missing_tool", autonomy.failure_diagnosis_categories)
        self.assertIn("timeout", autonomy.failure_diagnosis_categories)
        self.assertIn("parser_failure", autonomy.failure_diagnosis_categories)
        self.assertIn("authentication_required", autonomy.failure_diagnosis_categories)
        self.assertIn("policy_blocked", autonomy.failure_diagnosis_categories)
        self.assertIn("operator_intent_blocked", autonomy.failure_diagnosis_categories)

        self.assertEqual(autonomy.script_safety.generated_helper_scope, "engagement_local_only")
        self.assertIn("subprocess", autonomy.script_safety.forbidden_imports)
        self.assertIn("socket", autonomy.script_safety.forbidden_imports)
        self.assertIn("os.system", autonomy.script_safety.forbidden_calls)
        self.assertIn("eval", autonomy.script_safety.forbidden_calls)
        self.assertIn("exec", autonomy.script_safety.forbidden_calls)
        self.assertIn("importlib.import_module", autonomy.script_safety.forbidden_calls)
        self.assertIn("broad_filesystem_writes", autonomy.script_safety.rejected_behaviors)
        self.assertIn("unapproved_socket_or_network_behavior", autonomy.script_safety.rejected_behaviors)

        validator = ScriptSafetyValidator()
        self.assertTrue(validator.validate("import json\ndef main(raw): return json.loads(raw)\n")[0])
        self.assertFalse(validator.validate("import socket\nsocket.socket()\n")[0])
        self.assertFalse(validator.validate("import os\nos.system('id')\n")[0])
        self.assertFalse(validator.validate("import importlib\nimportlib.import_module('x')\n")[0])
        self.assertFalse(validator.validate("with open('/tmp/x', 'w') as fh:\n    fh.write('x')\n")[0])

    def test_methodology_compiler_outputs_proposal_local_artifacts_only(self) -> None:
        autonomy = StructuredAutonomyCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(autonomy.methodology_compiler.input_format, "markdown")
        self.assertEqual(autonomy.methodology_compiler.output_root, "proposals/methodology")
        self.assertIn("proposal_local_artifacts_only", autonomy.methodology_compiler.rules)
        self.assertIn("baseline_catalogs_are_not_mutated_by_compiler_output", autonomy.methodology_compiler.rules)
        self.assertIn("operator_review_required_before_promotion", autonomy.methodology_compiler.rules)

        proposal = MethodologyCompiler(Path("proposals/methodology")).compile_markdown("# Web Review\nSteps", name="web_review")
        self.assertEqual(proposal.kind, "methodology")
        self.assertEqual(proposal.generated_artifacts[0].path, Path("proposals/methodology/web_review/proposal.md"))
        self.assertIn("Strict catalog validation.", proposal.promotion_requirements)

    def test_structured_autonomy_catalog_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "structured_autonomy.yaml").write_text(
                "id: primordial_structured_autonomy\n"
                "source_path: docs/structured_autonomy.md\n"
                "status: migrated_autonomy_scaffold\n"
                "authority: typed_scaffold_description_not_policy_authority\n"
                "scaffold_support: []\n"
                "tool_inventory_checks: []\n"
                "tooling_gap_substitutions: []\n"
                "failure_diagnosis_categories: []\n"
                "script_safety:\n"
                "  generated_helper_scope: engagement_local_only\n"
                "  forbidden_imports: []\n"
                "  forbidden_calls: []\n"
                "  rejected_behaviors: []\n"
                "methodology_compiler:\n"
                "  input_format: markdown\n"
                "  output_root: proposals/methodology\n"
                "  rules: []\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                StructuredAutonomyCatalog(root).load()


if __name__ == "__main__":
    unittest.main()
