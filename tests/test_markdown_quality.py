from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
import unittest

from primordial.core.quality.markdown import (
    audit_markdown_sources,
    main,
    quarantine_generated_markdown,
    quarantine_migrated_markdown,
)


class MarkdownQualityTests(unittest.TestCase):
    def test_tracked_markdown_requires_migration_or_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _git(root, "init", "-q")
            (root / "README.md").write_text("# Project\n", encoding="utf-8")
            (root / "docs").mkdir()
            (root / "docs" / "legacy.md").write_text("# Legacy source of truth\n", encoding="utf-8")
            _git(root, "add", "README.md", "docs/legacy.md")

            audit = audit_markdown_sources(root)

        self.assertEqual(audit.summary["tracked_markdown_count"], 2)
        self.assertEqual(audit.summary["requires_action_count"], 2)
        self.assertEqual(
            {record.path: record.status for record in audit.records},
            {
                "README.md": "requires_migration_or_quarantine",
                "docs/legacy.md": "requires_migration_or_quarantine",
            },
        )
        self.assertTrue(all(record.ingest_allowed is False for record in audit.records))
        self.assertTrue(all(record.operational_retrieval_allowed is False for record in audit.records))

    def test_ignored_source_markdown_requires_migration_or_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _git(root, "init", "-q")
            (root / ".gitignore").write_text("docs/HUMAN_CHANGE_GUIDE.md\n", encoding="utf-8")
            guide_path = root / "docs" / "HUMAN_CHANGE_GUIDE.md"
            guide_path.parent.mkdir()
            guide_path.write_text("# Human Change Guide\n", encoding="utf-8")
            runtime_path = root / "runtime" / "test-results" / "generated.md"
            runtime_path.parent.mkdir(parents=True)
            runtime_path.write_text("# Runtime output\n", encoding="utf-8")
            _git(root, "add", ".gitignore")

            audit = audit_markdown_sources(root)

        records = {record.path: record for record in audit.records}
        self.assertIn("docs/HUMAN_CHANGE_GUIDE.md", records)
        self.assertNotIn("runtime/test-results/generated.md", records)
        self.assertEqual(records["docs/HUMAN_CHANGE_GUIDE.md"].status, "requires_migration_or_quarantine")
        self.assertEqual(records["docs/HUMAN_CHANGE_GUIDE.md"].planned_action, "archive_quarantine")
        self.assertEqual(records["docs/HUMAN_CHANGE_GUIDE.md"].source_class, "source_markdown")

    def test_quarantined_markdown_with_deny_markers_is_not_actionable_source_of_truth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _git(root, "init", "-q")
            quarantine_path = root / "runtime" / "quarantine" / "export.md"
            quarantine_path.parent.mkdir(parents=True)
            quarantine_path.write_text(
                "---\ningest_allowed: false\noperational_retrieval_allowed: false\n---\n# Export\n",
                encoding="utf-8",
            )
            _git(root, "add", "runtime/quarantine/export.md")

            audit = audit_markdown_sources(root)

        self.assertEqual(audit.summary["tracked_markdown_count"], 1)
        self.assertEqual(audit.summary["requires_action_count"], 0)
        self.assertEqual(audit.records[0].status, "quarantined")

    def test_markdown_quality_cli_returns_failure_when_action_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _git(root, "init", "-q")
            (root / "notes.md").write_text("# Notes\n", encoding="utf-8")
            _git(root, "add", "notes.md")
            output_path = root / "audit.json"

            result = main(["--root", str(root), "--json", str(output_path)])
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(result, 1)
        self.assertEqual(payload["summary"]["requires_action_count"], 1)
        self.assertEqual(payload["records"][0]["planned_action"], "archive_quarantine")

    def test_quarantine_generated_markdown_preserves_content_with_deny_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _git(root, "init", "-q")
            export_path = root / "findings" / "notion" / "alpha.htb" / "notion-export.md"
            export_path.parent.mkdir(parents=True)
            export_path.write_text("# Legacy Export\n\nGenerated target prose.\n", encoding="utf-8")
            readme_path = root / "README.md"
            readme_path.write_text("# Durable Docs\n", encoding="utf-8")
            _git(root, "add", "findings/notion/alpha.htb/notion-export.md", "README.md")

            result = quarantine_generated_markdown(root)
            audit = audit_markdown_sources(root)

            quarantine_path = (
                root
                / "runtime"
                / "quarantine"
                / "markdown"
                / "findings"
                / "notion"
                / "alpha.htb"
                / "notion-export.md"
            )
            self.assertEqual(result["summary"]["quarantined_count"], 1)
            self.assertFalse(export_path.exists())
            self.assertTrue(readme_path.exists())
            self.assertTrue(quarantine_path.exists())
            body = quarantine_path.read_text(encoding="utf-8")
            self.assertTrue(body.startswith("---\norigin: generated_export\n"))
            self.assertIn("ingest_allowed: false", body)
            self.assertIn("operational_retrieval_allowed: false", body)
            self.assertIn("# Legacy Export", body)
            self.assertEqual(audit.summary["quarantined_count"], 1)
            self.assertEqual(audit.summary["requires_action_count"], 1)
            self.assertEqual({record.path for record in audit.records}, {"README.md", str(quarantine_path.relative_to(root))})

    def test_quarantine_migrated_markdown_requires_explicit_migration_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _git(root, "init", "-q")
            agents_path = root / "AGENTS.md"
            agents_path.write_text("# Agent Rules\n\nDefault intent is recon_only.\n", encoding="utf-8")
            _git(root, "add", "AGENTS.md")

            result = quarantine_migrated_markdown(
                root,
                paths=("AGENTS.md",),
                migration_ref="catalog/policies/agent_runtime.yaml",
            )
            audit = audit_markdown_sources(root)

            quarantine_path = root / "runtime" / "quarantine" / "markdown" / "AGENTS.md"
            self.assertEqual(result["summary"]["quarantined_count"], 1)
            self.assertFalse(agents_path.exists())
            self.assertTrue(quarantine_path.exists())
            body = quarantine_path.read_text(encoding="utf-8")
            self.assertTrue(body.startswith("---\norigin: source_markdown\n"))
            self.assertIn("migration_ref: catalog/policies/agent_runtime.yaml", body)
            self.assertIn("ingest_allowed: false", body)
            self.assertIn("operational_retrieval_allowed: false", body)
            self.assertIn("Default intent is recon_only.", body)
            self.assertEqual(audit.summary["quarantined_count"], 1)
            self.assertEqual(audit.summary["requires_action_count"], 0)


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["git", *args], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result


if __name__ == "__main__":
    unittest.main()
