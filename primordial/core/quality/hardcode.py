from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from primordial.labs.ctf import HardcodeScanner


TEXT_SUFFIXES = frozenset(
    {
        ".css",
        ".goal",
        ".html",
        ".instruct",
        ".js",
        ".json",
        ".jsx",
        ".md",
        ".prompt",
        ".py",
        ".toml",
        ".txt",
        ".yaml",
        ".yml",
    }
)
NON_SOURCE_PATH_PREFIXES = (
    ".git/",
    ".goal/",
    ".pytest_cache/",
    ".venv/",
    "AI_MODELS/",
    "ENV/",
    "agent_chat_api/runtime/",
    "artifacts/model_eval/",
    "chat_log/",
    "env/",
    "goal/",
    "node_modules/",
    "primordial-rag-preprocess/.pytest_cache/",
    "primordial-rag-preprocess/output/",
    "runtime/",
    "venv/",
)
NON_SOURCE_EXACT_PATHS = frozenset({"codex-goal.instruct"})


@dataclass(frozen=True, slots=True)
class HardcodeAuditRecord:
    path: str
    rule_id: str
    line: int
    severity: str
    status: str
    source_class: str
    message: str


@dataclass(frozen=True, slots=True)
class HardcodeAudit:
    records: tuple[HardcodeAuditRecord, ...]
    summary: dict[str, int]

    def as_payload(self) -> dict[str, Any]:
        return {
            "summary": dict(self.summary),
            "records": [asdict(record) for record in self.records],
        }


def audit_hardcoded_artifacts(
    root: str | Path = ".",
    *,
    box_names: tuple[str, ...] = (),
    hidden_solution_snippets: tuple[str, ...] = (),
) -> HardcodeAudit:
    repo_root = Path(root)
    paths = _text_paths(repo_root)
    files = {path: (repo_root / path).read_text(encoding="utf-8", errors="ignore") for path in paths}
    try:
        scan = HardcodeScanner.scan(
            files,
            box_names=box_names,
            hidden_solution_snippets=hidden_solution_snippets,
        )
    except TypeError as exc:
        if "box_names" not in str(exc):
            raise
        scan = HardcodeScanner.scan(
            files,
            hidden_solution_snippets=hidden_solution_snippets,
        )
    records = tuple(
        HardcodeAuditRecord(
            path=finding.path,
            rule_id=finding.rule_id,
            line=finding.line,
            severity=finding.severity,
            status="violation",
            source_class=_source_class(finding.path),
            message=finding.message,
        )
        for finding in scan.findings
    )
    return HardcodeAudit(
        records=records,
        summary={
            "scanned_file_count": len(paths),
            "violation_count": len(records),
            "hard_fail_count": sum(1 for record in records if record.severity == "hard_fail"),
            "review_count": sum(1 for record in records if record.severity == "review"),
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit hardcoded CTF/challenge artifacts in source text files.")
    parser.add_argument("--root", default=".", help="Repository root.")
    parser.add_argument("--json", help="Write audit JSON to this path.")
    parser.add_argument("--box-name", action="append", default=[], help="Challenge or box name that must not be hardcoded.")
    parser.add_argument(
        "--hidden-solution-snippet-file",
        action="append",
        default=[],
        help="File containing hidden solution text to match against the scanned tree.",
    )
    args = parser.parse_args(argv)

    audit = audit_hardcoded_artifacts(
        args.root,
        box_names=tuple(args.box_name),
        hidden_solution_snippets=_snippet_files(args.root, tuple(args.hidden_solution_snippet_file)),
    )
    body = json.dumps(audit.as_payload(), indent=2, sort_keys=True) + "\n"
    if args.json:
        Path(args.json).write_text(body, encoding="utf-8")
    else:
        print(body, end="")
    return 1 if audit.summary["violation_count"] else 0


def _text_paths(root: Path) -> tuple[str, ...]:
    paths = set(_git_paths(root, ["ls-files", "--cached"]))
    paths.update(_git_paths(root, ["ls-files", "--others", "--exclude-standard"]))
    if paths:
        return tuple(sorted(path for path in paths if _is_scannable_text_path(root, path)))
    return tuple(
        sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if _is_scannable_text_path(root, path.relative_to(root).as_posix())
        )
    )


def _git_paths(root: Path, args: list[str]) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        return ()
    return tuple(sorted(line.strip() for line in result.stdout.splitlines() if line.strip()))


def _is_scannable_text_path(root: Path, rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/")
    if normalized in NON_SOURCE_EXACT_PATHS:
        return False
    if "__pycache__" in Path(normalized).parts:
        return False
    if any(normalized.startswith(prefix) for prefix in NON_SOURCE_PATH_PREFIXES):
        return False
    path = root / rel_path
    return path.is_file() and path.suffix.lower() in TEXT_SUFFIXES


def _source_class(rel_path: str) -> str:
    if rel_path.startswith("tests/") or "/tests/" in rel_path:
        return "test"
    if rel_path.startswith("catalog/"):
        return "catalog"
    if rel_path.startswith("findings/"):
        return "operator_finding_artifact"
    if rel_path.endswith(".instruct") or rel_path.endswith(".goal") or rel_path.endswith(".prompt"):
        return "prompt_contract"
    return "source"


def _snippet_files(root: str | Path, paths: tuple[str, ...]) -> tuple[str, ...]:
    repo_root = Path(root)
    snippets = []
    for rel_path in paths:
        path = Path(rel_path)
        if not path.is_absolute():
            path = repo_root / path
        snippets.append(path.read_text(encoding="utf-8", errors="ignore"))
    return tuple(snippets)


if __name__ == "__main__":
    raise SystemExit(main())
