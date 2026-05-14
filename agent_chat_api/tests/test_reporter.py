from __future__ import annotations

import io
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

try:
    from agent_chat_api.tests.support import PACKAGE_ROOT
except ModuleNotFoundError:
    from support import PACKAGE_ROOT

from agent_chat_api.test_reporter import MarkdownTestResult, TestRecord, render_markdown_report, write_markdown_report


class ReporterTests(unittest.TestCase):
    def make_result(self) -> MarkdownTestResult:
        result = MarkdownTestResult(io.StringIO(), descriptions=True, verbosity=2)
        result.testsRun = 2
        result.records = [
            TestRecord("tests.test_example.Passing.test_one", "", "passed", 0.001),
            TestRecord("tests.test_example.Failing.test_two", "", "failed", 0.002, "assertion failed"),
        ]
        result.failures = [(object(), "assertion failed")]
        return result

    def test_render_markdown_report_contains_summary_and_case_table(self) -> None:
        now = datetime(2026, 5, 14, tzinfo=timezone.utc)
        markdown = render_markdown_report(root=PACKAGE_ROOT, result=self.make_result(), started_at=now, finished_at=now)
        self.assertIn("# Agent Chat API Test Results", markdown)
        self.assertIn("| Tests run | 2 |", markdown)
        self.assertIn("`tests.test_example.Passing.test_one`", markdown)
        self.assertIn("## Details", markdown)
        self.assertIn("assertion failed", markdown)

    def test_write_markdown_report_writes_timestamp_and_latest_files(self) -> None:
        now = datetime(2026, 5, 14, 12, 30, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory(dir=PACKAGE_ROOT) as tmp:
            report_path = write_markdown_report(
                root=PACKAGE_ROOT,
                result=self.make_result(),
                started_at=now,
                finished_at=now,
                output_dir=Path(tmp),
            )
            self.assertTrue(report_path.name.startswith("test-results-20260514T123000Z"))
            self.assertTrue(report_path.exists())
            self.assertTrue((report_path.parent / "latest.md").exists())

if __name__ == "__main__":
    unittest.main()
