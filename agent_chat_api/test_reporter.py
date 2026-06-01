from __future__ import annotations

import argparse
import json
import platform
import sys
import time
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO


@dataclass
class TestRecord:
    test_id: str
    description: str
    status: str
    elapsed_seconds: float
    detail: str = ""


class MarkdownTestResult(unittest.TextTestResult):
    def __init__(self, stream: TextIO, descriptions: bool, verbosity: int) -> None:
        super().__init__(stream, descriptions, verbosity)
        self.records: list[TestRecord] = []
        self._started_at: dict[unittest.case.TestCase, float] = {}

    def startTest(self, test: unittest.case.TestCase) -> None:
        self._started_at[test] = time.monotonic()
        super().startTest(test)

    def addSuccess(self, test: unittest.case.TestCase) -> None:
        super().addSuccess(test)
        self._record(test, "passed")

    def addFailure(self, test: unittest.case.TestCase, err: tuple[type[BaseException], BaseException, object]) -> None:
        super().addFailure(test, err)
        self._record(test, "failed", self._exc_info_to_string(err, test))

    def addError(self, test: unittest.case.TestCase, err: tuple[type[BaseException], BaseException, object]) -> None:
        super().addError(test, err)
        self._record(test, "error", self._exc_info_to_string(err, test))

    def addSkip(self, test: unittest.case.TestCase, reason: str) -> None:
        super().addSkip(test, reason)
        self._record(test, "skipped", reason)

    def addExpectedFailure(
        self,
        test: unittest.case.TestCase,
        err: tuple[type[BaseException], BaseException, object],
    ) -> None:
        super().addExpectedFailure(test, err)
        self._record(test, "expected_failure", self._exc_info_to_string(err, test))

    def addUnexpectedSuccess(self, test: unittest.case.TestCase) -> None:
        super().addUnexpectedSuccess(test)
        self._record(test, "unexpected_success")

    def _record(self, test: unittest.case.TestCase, status: str, detail: str = "") -> None:
        elapsed = time.monotonic() - self._started_at.pop(test, time.monotonic())
        self.records.append(
            TestRecord(
                test_id=test.id(),
                description=test.shortDescription() or "",
                status=status,
                elapsed_seconds=elapsed,
                detail=detail.strip(),
            )
        )


class MarkdownTestRunner(unittest.TextTestRunner):
    resultclass = MarkdownTestResult


GENERATED_MARKDOWN_METADATA = {
    "source_class": "generated_markdown",
    "authoritative": False,
    "ingest_allowed": False,
    "operational_retrieval_allowed": False,
    "generated_by": "agent_chat_api.test_reporter",
}


def default_output_dir(root: Path) -> Path:
    return root / "runtime" / "test-results"


def run_suite(
    *,
    root: Path,
    start_dir: Path,
    pattern: str = "test*.py",
    verbosity: int = 2,
    stream: TextIO | None = None,
) -> tuple[MarkdownTestResult, datetime, datetime]:
    started_at = datetime.now(timezone.utc)
    suite = unittest.defaultTestLoader.discover(str(start_dir), pattern=pattern, top_level_dir=str(root.parent))
    runner = MarkdownTestRunner(stream=stream or sys.stdout, verbosity=verbosity)
    result = runner.run(suite)
    finished_at = datetime.now(timezone.utc)
    if not isinstance(result, MarkdownTestResult):
        raise TypeError("expected MarkdownTestResult")
    return result, started_at, finished_at


def write_markdown_report(
    *,
    root: Path,
    result: MarkdownTestResult,
    started_at: datetime,
    finished_at: datetime,
    output_dir: Path,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = finished_at.strftime("%Y%m%dT%H%M%SZ")
    report_path = output_dir / f"test-results-{stamp}.md"
    latest_path = output_dir / "latest.md"
    markdown = render_markdown_report(root=root, result=result, started_at=started_at, finished_at=finished_at)
    report_path.write_text(markdown, encoding="utf-8")
    latest_path.write_text(markdown, encoding="utf-8")
    _write_metadata(report_path)
    _write_metadata(latest_path)
    return report_path


def render_markdown_report(
    *,
    root: Path,
    result: MarkdownTestResult,
    started_at: datetime,
    finished_at: datetime,
) -> str:
    elapsed = (finished_at - started_at).total_seconds()
    status = "PASS" if result.wasSuccessful() else "FAIL"
    passed = len([record for record in result.records if record.status == "passed"])
    lines = [
        "# Agent Chat API Test Results",
        "",
        f"- Status: `{status}`",
        f"- Started: `{started_at.isoformat()}`",
        f"- Finished: `{finished_at.isoformat()}`",
        f"- Duration: `{elapsed:.3f}s`",
        f"- Python: `{platform.python_version()}`",
        f"- Platform: `{platform.platform()}`",
        f"- Root: `{root}`",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Tests run | {result.testsRun} |",
        f"| Passed | {passed} |",
        f"| Failed | {len(result.failures)} |",
        f"| Errors | {len(result.errors)} |",
        f"| Skipped | {len(result.skipped)} |",
        f"| Expected failures | {len(result.expectedFailures)} |",
        f"| Unexpected successes | {len(result.unexpectedSuccesses)} |",
        "",
        "## Test Cases",
        "",
        "| Status | Seconds | Test | Description |",
        "| --- | ---: | --- | --- |",
    ]
    for record in result.records:
        lines.append(
            f"| `{record.status}` | {record.elapsed_seconds:.3f} | `{_escape_pipe(record.test_id)}` | "
            f"{_escape_pipe(record.description)} |"
        )

    details = [record for record in result.records if record.detail]
    if details:
        lines.extend(["", "## Details", ""])
        for record in details:
            lines.extend(
                [
                    f"### `{record.test_id}`",
                    "",
                    "```text",
                    record.detail,
                    "```",
                    "",
                ]
            )
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Run Agent Chat API tests and write a Markdown report")
    parser.add_argument("--output-dir", default=str(default_output_dir(root)), help="Directory for timestamped Markdown reports")
    parser.add_argument("--pattern", default="test*.py", help="unittest discovery pattern")
    parser.add_argument("--quiet", action="store_true", help="Use low-verbosity test output")
    args = parser.parse_args(argv)

    result, started_at, finished_at = run_suite(
        root=root,
        start_dir=root / "tests",
        pattern=args.pattern,
        verbosity=1 if args.quiet else 2,
    )
    report_path = write_markdown_report(
        root=root,
        result=result,
        started_at=started_at,
        finished_at=finished_at,
        output_dir=Path(args.output_dir),
    )
    print(f"\nMarkdown report: {report_path}")
    return 0 if result.wasSuccessful() else 1


def _escape_pipe(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _write_metadata(markdown_path: Path) -> None:
    metadata = dict(GENERATED_MARKDOWN_METADATA)
    metadata["path"] = markdown_path.name
    markdown_path.with_suffix(markdown_path.suffix + ".metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
