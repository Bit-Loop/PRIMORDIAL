from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from primordial.config import AppConfig
from primordial.core.domain.enums import ScopeProfile
from primordial.runtime import PrimordialRuntime
from tests.support import fixture_ip


PIRATE_IP = fixture_ip(10, 129, 47, 117)


class FindingsContextTests(unittest.TestCase):
    def test_register_target_creates_durable_findings_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()

            runtime.register_target(
                handle="pirate.htb",
                display_name="HTB Pirate",
                profile=ScopeProfile.HACK_THE_BOX,
                assets=["pirate.htb", PIRATE_IP],
            )
            payload = runtime.findings_context_payload(target="pirate.htb", include_guidance=True)
            workspace = payload["workspace"]

            self.assertTrue(Path(workspace["guidance_path"]).exists())
            self.assertTrue(Path(workspace["findings_path"]).exists())
            self.assertTrue(Path(workspace["evidence_path"]).exists())
            self.assertIn("AI Agent Guidance", workspace["guidance"])
            runtime.shutdown()

    def test_initialize_creates_machine_readable_workspace_manifest_not_readme(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()

            manifest_path = config.findings_dir / "workspace.yaml"

            self.assertTrue(manifest_path.exists())
            self.assertFalse((config.findings_dir / "README.md").exists())
            body = manifest_path.read_text(encoding="utf-8")
            self.assertIn("id: primordial_findings_workspace", body)
            self.assertIn("guidance_path: targets/<target>/guidance.md", body)
            self.assertIn("notion_export_path: notion/<target>/notion-export.md", body)
            runtime.shutdown()

    def test_sync_findings_context_exports_local_notion_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.register_target(
                handle="pirate.htb",
                display_name="HTB Pirate",
                profile=ScopeProfile.HACK_THE_BOX,
                assets=["pirate.htb"],
            )

            outcome = runtime.sync_findings_context_exports()
            export_path = Path(outcome["synced"][0]["workspace"]["notion_export_path"])

            self.assertTrue(export_path.exists())
            self.assertIn("HTB Pirate Notion Export", export_path.read_text(encoding="utf-8"))
            runtime.shutdown()

    def test_sync_findings_context_exports_canonical_notion_sections(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.register_target(
                handle="pirate.htb",
                display_name="HTB Pirate",
                profile=ScopeProfile.HACK_THE_BOX,
                assets=["pirate.htb"],
            )

            outcome = runtime.sync_findings_context_exports()
            export_path = Path(outcome["synced"][0]["workspace"]["notion_export_path"])
            body = export_path.read_text(encoding="utf-8")

            for section in (
                "## Authoritative Runtime State",
                "## Observed Evidence",
                "## Reviewed Findings",
                "## Operator Notes",
                "## Candidate Tasks",
                "## Hypotheses",
                "## AI Summaries",
                "## RAG Advisory Material",
                "## Blocked Actions",
                "## CTFd Scoreboard Projection",
                "## GitHub Links",
                "## Sync Log / Conflicts",
            ):
                self.assertIn(section, body)
            self.assertNotIn("## Findings", body)
            self.assertNotIn("## Open Interests", body)
            self.assertNotIn("## Recent Notes", body)
            self.assertNotIn("## Evidence References", body)
            runtime.shutdown()

    def test_sync_findings_context_marks_notion_export_non_ingestable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.register_target(
                handle="pirate.htb",
                display_name="HTB Pirate",
                profile=ScopeProfile.HACK_THE_BOX,
                assets=["pirate.htb"],
            )

            outcome = runtime.sync_findings_context_exports()
            export_path = Path(outcome["synced"][0]["workspace"]["notion_export_path"])
            body = export_path.read_text(encoding="utf-8")

            self.assertIn("origin: generated_export", body)
            self.assertIn("ingest_allowed: false", body)
            self.assertIn("operational_retrieval_allowed: false", body)
            runtime.shutdown()

    def test_audit_findings_context_exports_reports_missing_deny_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.register_target(
                handle="pirate.htb",
                display_name="HTB Pirate",
                profile=ScopeProfile.HACK_THE_BOX,
                assets=["pirate.htb"],
            )
            payload = runtime.findings_context_payload(target="pirate.htb", include_guidance=False)
            export_path = Path(payload["workspace"]["notion_export_path"])
            export_path.write_text("# Legacy Notion Export\n\nGenerated prose without deny metadata.\n", encoding="utf-8")

            audit = runtime.audit_findings_context_exports()

            self.assertEqual(audit["summary"]["files_seen"], 1)
            self.assertEqual(audit["summary"]["quarantine_required"], 1)
            self.assertEqual(audit["generated_exports"][0]["status"], "requires_quarantine")
            self.assertEqual(
                audit["generated_exports"][0]["missing_metadata"],
                ["origin", "ingest_allowed", "operational_retrieval_allowed"],
            )
            runtime.shutdown()

    def test_audit_findings_context_requires_generated_export_marker_block(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.register_target(
                handle="pirate.htb",
                display_name="HTB Pirate",
                profile=ScopeProfile.HACK_THE_BOX,
                assets=["pirate.htb"],
            )
            payload = runtime.findings_context_payload(target="pirate.htb", include_guidance=False)
            export_path = Path(payload["workspace"]["notion_export_path"])
            export_path.write_text(
                "# Legacy Notion Export\n\n"
                "These body lines must not satisfy export metadata requirements.\n"
                "origin: generated_export\n"
                "ingest_allowed: false\n"
                "operational_retrieval_allowed: false\n",
                encoding="utf-8",
            )

            audit = runtime.audit_findings_context_exports()

            self.assertEqual(audit["summary"]["files_seen"], 1)
            self.assertEqual(audit["summary"]["quarantine_required"], 1)
            self.assertEqual(audit["generated_exports"][0]["status"], "requires_quarantine")
            self.assertEqual(
                audit["generated_exports"][0]["missing_metadata"],
                ["origin", "ingest_allowed", "operational_retrieval_allowed"],
            )
            runtime.shutdown()

    def test_audit_findings_context_exports_includes_quarantine_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.register_target(
                handle="pirate.htb",
                display_name="HTB Pirate",
                profile=ScopeProfile.HACK_THE_BOX,
                assets=["pirate.htb"],
            )
            payload = runtime.findings_context_payload(target="pirate.htb", include_guidance=False)
            export_path = Path(payload["workspace"]["notion_export_path"])
            export_path.write_text("# Legacy Notion Export\n\nGenerated prose without deny metadata.\n", encoding="utf-8")

            audit = runtime.audit_findings_context_exports()
            record = audit["generated_exports"][0]

            self.assertEqual(record["status"], "requires_quarantine")
            self.assertEqual(record["planned_action"], "archive_quarantine")
            self.assertEqual(
                record["quarantine_metadata"],
                {
                    "origin": "generated_export",
                    "ingest_allowed": False,
                    "operational_retrieval_allowed": False,
                },
            )
            self.assertIn("findings/notion/_archive/pirate.htb/notion-export.md", record["archive_path"])
            self.assertTrue(export_path.exists())
            runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
