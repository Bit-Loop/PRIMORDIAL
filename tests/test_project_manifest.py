from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from primordial.cli import build_parser
from primordial.core.catalog.loader import CatalogValidationError
from primordial.core.catalog.project_manifest import ProjectManifestCatalog


REPO_ROOT = Path(__file__).resolve().parents[1]


class ProjectManifestTests(unittest.TestCase):
    def test_root_readme_behavior_is_represented_as_typed_project_manifest(self) -> None:
        manifest = ProjectManifestCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertEqual(manifest.id, "primordial")
        self.assertEqual(manifest.runtime_model, "local_first_control_plane")
        self.assertIn("authorized_security_testing", manifest.domains)
        self.assertIn("durable_workflow_state", manifest.authority_sources)
        self.assertIn("explicit_operator_controls", manifest.authority_sources)
        self.assertFalse(manifest.markdown_authoritative)

    def test_project_manifest_cli_inventory_matches_live_parser(self) -> None:
        manifest = ProjectManifestCatalog(REPO_ROOT / "catalog" / "project").load()
        parser_commands = _parser_commands()

        self.assertEqual(set(manifest.cli_commands), parser_commands)

    def test_project_manifest_preserves_hard_boundaries_and_poc_gate(self) -> None:
        manifest = ProjectManifestCatalog(REPO_ROOT / "catalog" / "project").load()

        self.assertIn("ddos_always_forbidden", manifest.hard_boundaries)
        self.assertIn("explicit_scope_required", manifest.hard_boundaries)
        self.assertIn("ambiguous_scope_requires_operator_clarification", manifest.hard_boundaries)
        self.assertEqual(
            manifest.poc_execution_gate,
            (
                "autonomy_mode_supervised_auto_or_high_autonomy",
                "PRIMORDIAL_ALLOW_EXPLOITATIVE_ACTIONS=1",
                "agent_safety_approval",
                "explicit_scope_evidence_non_dos_limits_and_timeout",
            ),
        )

    def test_project_manifest_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "primordial.yaml").write_text(
                "id: primordial\n"
                "runtime_model: local_first_control_plane\n"
                "domains: []\n"
                "authority_sources: []\n"
                "core_principles: []\n"
                "implemented_surfaces: []\n"
                "cli_commands: []\n"
                "runtime_directories: []\n"
                "required_environment: []\n"
                "policy_environment: []\n"
                "agent_chat_environment: []\n"
                "hard_boundaries: []\n"
                "poc_execution_gate: []\n"
                "markdown_authoritative: false\n"
                "unknown: true\n",
                encoding="utf-8",
            )

            with self.assertRaises(CatalogValidationError):
                ProjectManifestCatalog(root).load()


def _parser_commands() -> set[str]:
    parser = build_parser()
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if choices:
            return set(choices)
    raise AssertionError("argparse parser has no subcommand choices")


if __name__ == "__main__":
    unittest.main()
