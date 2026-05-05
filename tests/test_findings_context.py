from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from primordial.config import AppConfig
from primordial.core.domain.enums import ScopeProfile
from primordial.runtime import PrimordialRuntime


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
                assets=["pirate.htb", "10.129.47.117"],
            )
            payload = runtime.findings_context_payload(target="pirate.htb", include_guidance=True)
            workspace = payload["workspace"]

            self.assertTrue(Path(workspace["guidance_path"]).exists())
            self.assertTrue(Path(workspace["findings_path"]).exists())
            self.assertTrue(Path(workspace["evidence_path"]).exists())
            self.assertIn("AI Agent Guidance", workspace["guidance"])
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


if __name__ == "__main__":
    unittest.main()
