from __future__ import annotations

import argparse
import ast
import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


DEFAULT_MAX_FILE_LINES = 500
DEFAULT_MAX_FUNCTION_LINES = 80
DEFAULT_MAX_CLASS_LINES = 300
NON_SOURCE_PATH_PREFIXES = (
    ".git/",
    ".pytest_cache/",
    ".venv/",
    "AI_MODELS/",
    "ENV/",
    "env/",
    "goal/archive/",
    "node_modules/",
    "primordial-rag-preprocess/.pytest_cache/",
    "primordial-rag-preprocess/output/",
    "runtime/",
    "venv/",
)


@dataclass(frozen=True, slots=True)
class StructureAuditRecord:
    path: str
    kind: str
    name: str
    line_count: int
    max_lines: int
    start_line: int
    end_line: int
    status: str
    reason: str


@dataclass(frozen=True, slots=True)
class StructureAudit:
    records: tuple[StructureAuditRecord, ...]
    summary: dict[str, int]

    def as_payload(self) -> dict[str, Any]:
        return {
            "summary": dict(self.summary),
            "records": [asdict(record) for record in self.records],
        }


def audit_structure(
    root: str | Path = ".",
    *,
    max_file_lines: int = DEFAULT_MAX_FILE_LINES,
    max_function_lines: int = DEFAULT_MAX_FUNCTION_LINES,
    max_class_lines: int = DEFAULT_MAX_CLASS_LINES,
) -> StructureAudit:
    repo_root = Path(root)
    paths = _python_paths(repo_root)
    records: list[StructureAuditRecord] = []
    for rel_path in paths:
        records.extend(
            _audit_file(
                repo_root / rel_path,
                rel_path=rel_path,
                max_file_lines=max_file_lines,
                max_function_lines=max_function_lines,
                max_class_lines=max_class_lines,
            )
        )
    return StructureAudit(
        records=tuple(records),
        summary={
            "python_file_count": len(paths),
            "violation_count": len(records),
            "module_violation_count": sum(1 for record in records if record.kind == "module"),
            "function_violation_count": sum(1 for record in records if record.kind == "function"),
            "class_violation_count": sum(1 for record in records if record.kind == "class"),
            "parse_error_count": sum(1 for record in records if record.kind == "parse_error"),
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit Python file, function, and class size limits.")
    parser.add_argument("--root", default=".", help="Repository root.")
    parser.add_argument("--json", help="Write audit JSON to this path.")
    parser.add_argument("--max-file-lines", default=DEFAULT_MAX_FILE_LINES, type=int)
    parser.add_argument("--max-function-lines", default=DEFAULT_MAX_FUNCTION_LINES, type=int)
    parser.add_argument("--max-class-lines", default=DEFAULT_MAX_CLASS_LINES, type=int)
    args = parser.parse_args(argv)

    audit = audit_structure(
        args.root,
        max_file_lines=args.max_file_lines,
        max_function_lines=args.max_function_lines,
        max_class_lines=args.max_class_lines,
    )
    body = json.dumps(audit.as_payload(), indent=2, sort_keys=True) + "\n"
    if args.json:
        Path(args.json).write_text(body, encoding="utf-8")
    else:
        print(body, end="")
    return 1 if audit.summary["violation_count"] else 0


def _audit_file(
    path: Path,
    *,
    rel_path: str,
    max_file_lines: int,
    max_function_lines: int,
    max_class_lines: int,
) -> tuple[StructureAuditRecord, ...]:
    body = path.read_text(encoding="utf-8")
    line_count = len(body.splitlines())
    records: list[StructureAuditRecord] = []
    if line_count > max_file_lines:
        records.append(
            _record(
                rel_path,
                kind="module",
                name=rel_path,
                line_count=line_count,
                max_lines=max_file_lines,
                start_line=1,
                end_line=line_count,
            )
        )
    try:
        tree = ast.parse(body, filename=rel_path)
    except SyntaxError as exc:
        return (
            StructureAuditRecord(
                path=rel_path,
                kind="parse_error",
                name=rel_path,
                line_count=0,
                max_lines=0,
                start_line=exc.lineno or 0,
                end_line=exc.end_lineno or exc.lineno or 0,
                status="violation",
                reason=str(exc),
            ),
        )
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            records.extend(_audit_node(rel_path, node, kind="function", max_lines=max_function_lines))
        elif isinstance(node, ast.ClassDef):
            records.extend(_audit_node(rel_path, node, kind="class", max_lines=max_class_lines))
    return tuple(records)


def _audit_node(
    rel_path: str,
    node: ast.AST,
    *,
    kind: str,
    max_lines: int,
) -> tuple[StructureAuditRecord, ...]:
    start_line = getattr(node, "lineno", 0)
    end_line = getattr(node, "end_lineno", start_line)
    line_count = end_line - start_line + 1 if start_line and end_line else 0
    if line_count <= max_lines:
        return ()
    return (
        _record(
            rel_path,
            kind=kind,
            name=getattr(node, "name", rel_path),
            line_count=line_count,
            max_lines=max_lines,
            start_line=start_line,
            end_line=end_line,
        ),
    )


def _record(
    rel_path: str,
    *,
    kind: str,
    name: str,
    line_count: int,
    max_lines: int,
    start_line: int,
    end_line: int,
) -> StructureAuditRecord:
    return StructureAuditRecord(
        path=rel_path,
        kind=kind,
        name=name,
        line_count=line_count,
        max_lines=max_lines,
        start_line=start_line,
        end_line=end_line,
        status="violation",
        reason=f"{kind} has {line_count} line(s), limit is {max_lines}",
    )


def _python_paths(root: Path) -> tuple[str, ...]:
    paths = set(_git_paths(root, ["ls-files", "--cached", "*.py"]))
    paths.update(_git_paths(root, ["ls-files", "--others", "--exclude-standard", "*.py"]))
    if paths:
        return tuple(sorted(path for path in paths if _is_source_python_path(root, path)))
    return tuple(
        sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*.py")
            if _is_source_python_path(root, path.relative_to(root).as_posix())
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


def _is_source_python_path(root: Path, rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/")
    if "__pycache__" in Path(normalized).parts:
        return False
    return (root / rel_path).is_file() and not any(normalized.startswith(prefix) for prefix in NON_SOURCE_PATH_PREFIXES)


if __name__ == "__main__":
    raise SystemExit(main())
