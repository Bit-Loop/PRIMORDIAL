from __future__ import annotations

import argparse
import ast
import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


DEFAULT_FORBIDDEN_EDGES = (
    ("primordial.core", "primordial.app"),
    ("primordial.core", "primordial.gui"),
    ("primordial.core", "primordial.cli"),
    ("primordial.modes", "primordial.app"),
    ("primordial.adapters", "primordial.app"),
)
DEFAULT_ALLOWED_EDGES = (
    ("primordial.core.web", "primordial.app.runtime"),
)
NON_SOURCE_PATH_PREFIXES = (
    ".git/",
    ".pytest_cache/",
    ".venv/",
    "AI_MODELS/",
    "ENV/",
    "env/",
    "goal/",
    "node_modules/",
    "primordial-rag-preprocess/.pytest_cache/",
    "primordial-rag-preprocess/output/",
    "runtime/",
    "venv/",
)


@dataclass(frozen=True, slots=True)
class ImportAuditRecord:
    path: str
    kind: str
    importer: str
    imported: str
    line: int
    cycle: tuple[str, ...]
    status: str
    reason: str


@dataclass(frozen=True, slots=True)
class ImportAudit:
    records: tuple[ImportAuditRecord, ...]
    summary: dict[str, int]

    def as_payload(self) -> dict[str, Any]:
        return {
            "summary": dict(self.summary),
            "records": [asdict(record) for record in self.records],
        }


@dataclass(frozen=True, slots=True)
class _ImportEdge:
    path: str
    importer: str
    requested: str
    imported: str
    line: int


def audit_imports(
    root: str | Path = ".",
    *,
    forbidden_edges: tuple[tuple[str, str], ...] = DEFAULT_FORBIDDEN_EDGES,
    allowed_edges: tuple[tuple[str, str], ...] = DEFAULT_ALLOWED_EDGES,
) -> ImportAudit:
    repo_root = Path(root)
    paths = _python_paths(repo_root)
    modules = {path: _module_name(path) for path in paths}
    module_paths = {module: path for path, module in modules.items() if module}
    records: list[ImportAuditRecord] = []
    edges: list[_ImportEdge] = []
    for rel_path, module in modules.items():
        parsed_edges, parse_error = _parse_import_edges(repo_root / rel_path, rel_path=rel_path, module=module)
        if parse_error is not None:
            records.append(parse_error)
        edges.extend(_resolve_local_edges(parsed_edges, module_paths))
    records.extend(_forbidden_dependency_records(edges, forbidden_edges, allowed_edges))
    records.extend(_cycle_records(edges, module_paths))
    return ImportAudit(
        records=tuple(records),
        summary={
            "python_file_count": len(paths),
            "import_edge_count": len(edges),
            "violation_count": len(records),
            "cycle_count": sum(1 for record in records if record.kind == "import_cycle"),
            "forbidden_dependency_count": sum(1 for record in records if record.kind == "forbidden_dependency"),
            "parse_error_count": sum(1 for record in records if record.kind == "parse_error"),
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit Python import cycles and dependency-boundary violations.")
    parser.add_argument("--root", default=".", help="Repository root.")
    parser.add_argument("--json", help="Write audit JSON to this path.")
    parser.add_argument(
        "--forbid",
        action="append",
        default=[],
        metavar="IMPORTER:IMPORTED",
        help="Add a forbidden import edge prefix pair.",
    )
    args = parser.parse_args(argv)

    forbidden_edges = DEFAULT_FORBIDDEN_EDGES + tuple(_parse_edge(item) for item in args.forbid)
    audit = audit_imports(args.root, forbidden_edges=forbidden_edges)
    body = json.dumps(audit.as_payload(), indent=2, sort_keys=True) + "\n"
    if args.json:
        Path(args.json).write_text(body, encoding="utf-8")
    else:
        print(body, end="")
    return 1 if audit.summary["violation_count"] else 0


def _parse_import_edges(path: Path, *, rel_path: str, module: str) -> tuple[tuple[_ImportEdge, ...], ImportAuditRecord | None]:
    try:
        body = path.read_text(encoding="utf-8")
        tree = ast.parse(body, filename=rel_path)
    except SyntaxError as exc:
        return (), ImportAuditRecord(
            path=rel_path,
            kind="parse_error",
            importer=module,
            imported="",
            line=exc.lineno or 0,
            cycle=(),
            status="violation",
            reason=str(exc),
        )
    package = _package_name(rel_path, module)
    edges: list[_ImportEdge] = []
    for node in ast.walk(tree):
        for requested in _requested_imports(node, package):
            edges.append(
                _ImportEdge(
                    path=rel_path,
                    importer=module,
                    requested=requested,
                    imported="",
                    line=getattr(node, "lineno", 0),
                )
            )
    return tuple(edges), None


def _requested_imports(node: ast.AST, package: str) -> tuple[str, ...]:
    if isinstance(node, ast.Import):
        return tuple(alias.name for alias in node.names)
    if isinstance(node, ast.ImportFrom):
        base = _absolute_import_base(node.module or "", level=node.level, package=package)
        targets = []
        for alias in node.names:
            if alias.name == "*":
                targets.append(base)
            elif base:
                targets.append(f"{base}.{alias.name}")
            else:
                targets.append(alias.name)
        return tuple(target for target in targets if target)
    return ()


def _resolve_local_edges(edges: tuple[_ImportEdge, ...], module_paths: dict[str, str]) -> tuple[_ImportEdge, ...]:
    resolved = []
    known_modules = frozenset(module_paths)
    for edge in edges:
        imported = _nearest_known_module(edge.requested, known_modules)
        if not imported or imported == edge.importer:
            continue
        resolved.append(
            _ImportEdge(
                path=edge.path,
                importer=edge.importer,
                requested=edge.requested,
                imported=imported,
                line=edge.line,
            )
        )
    return tuple(resolved)


def _forbidden_dependency_records(
    edges: list[_ImportEdge],
    forbidden_edges: tuple[tuple[str, str], ...],
    allowed_edges: tuple[tuple[str, str], ...],
) -> tuple[ImportAuditRecord, ...]:
    records = []
    seen: set[tuple[str, str, int]] = set()
    for edge in edges:
        for importer_prefix, imported_prefix in forbidden_edges:
            if _edge_matches_any(edge, allowed_edges):
                continue
            if not (_matches_prefix(edge.importer, importer_prefix) and _matches_prefix(edge.imported, imported_prefix)):
                continue
            key = (edge.importer, edge.imported, edge.line)
            if key in seen:
                continue
            seen.add(key)
            records.append(
                ImportAuditRecord(
                    path=edge.path,
                    kind="forbidden_dependency",
                    importer=edge.importer,
                    imported=edge.imported,
                    line=edge.line,
                    cycle=(),
                    status="violation",
                    reason=f"{edge.importer} must not import {edge.imported}",
                )
            )
    return tuple(records)


def _cycle_records(edges: list[_ImportEdge], module_paths: dict[str, str]) -> tuple[ImportAuditRecord, ...]:
    graph: dict[str, set[str]] = {module: set() for module in module_paths}
    for edge in edges:
        graph.setdefault(edge.importer, set()).add(edge.imported)
    records = []
    for component in _strongly_connected_components(graph):
        if len(component) < 2:
            continue
        cycle = _cycle_for_component(component, graph)
        records.append(
            ImportAuditRecord(
                path=module_paths[cycle[0]],
                kind="import_cycle",
                importer=cycle[0],
                imported=cycle[1],
                line=0,
                cycle=cycle,
                status="violation",
                reason="import cycle: " + " -> ".join(cycle),
            )
        )
    return tuple(sorted(records, key=lambda record: record.cycle))


def _strongly_connected_components(graph: dict[str, set[str]]) -> tuple[tuple[str, ...], ...]:
    index = 0
    stack: list[str] = []
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    on_stack: set[str] = set()
    components: list[tuple[str, ...]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for neighbor in sorted(graph.get(node, ())):
            if neighbor not in graph:
                continue
            if neighbor not in indices:
                visit(neighbor)
                lowlinks[node] = min(lowlinks[node], lowlinks[neighbor])
            elif neighbor in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[neighbor])
        if lowlinks[node] != indices[node]:
            return
        component = []
        while stack:
            item = stack.pop()
            on_stack.remove(item)
            component.append(item)
            if item == node:
                break
        components.append(tuple(sorted(component)))

    for node in sorted(graph):
        if node not in indices:
            visit(node)
    return tuple(components)


def _cycle_for_component(component: tuple[str, ...], graph: dict[str, set[str]]) -> tuple[str, ...]:
    start = sorted(component)[0]
    path = [start]
    visited = {start}
    current = start
    while True:
        neighbors = sorted(neighbor for neighbor in graph.get(current, ()) if neighbor in component)
        if start in neighbors and len(path) > 1:
            return tuple(path + [start])
        unvisited = [neighbor for neighbor in neighbors if neighbor not in visited]
        if not unvisited:
            return tuple(path + [start])
        current = unvisited[0]
        path.append(current)
        visited.add(current)


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


def _module_name(rel_path: str) -> str:
    path = Path(rel_path)
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _package_name(rel_path: str, module: str) -> str:
    if rel_path.endswith("/__init__.py"):
        return module
    return module.rpartition(".")[0]


def _absolute_import_base(module: str, *, level: int, package: str) -> str:
    if level == 0:
        return module
    parts = package.split(".") if package else []
    keep = max(0, len(parts) - level + 1)
    base_parts = parts[:keep]
    if module:
        base_parts.extend(module.split("."))
    return ".".join(part for part in base_parts if part)


def _nearest_known_module(requested: str, known_modules: frozenset[str]) -> str:
    parts = requested.split(".")
    while parts:
        candidate = ".".join(parts)
        if candidate in known_modules:
            return candidate
        parts.pop()
    return ""


def _matches_prefix(module: str, prefix: str) -> bool:
    return module == prefix or module.startswith(prefix + ".")


def _edge_matches_any(edge: _ImportEdge, pairs: tuple[tuple[str, str], ...]) -> bool:
    return any(_matches_prefix(edge.importer, left) and _matches_prefix(edge.imported, right) for left, right in pairs)


def _parse_edge(value: str) -> tuple[str, str]:
    importer, separator, imported = value.partition(":")
    if not separator or not importer.strip() or not imported.strip():
        raise argparse.ArgumentTypeError("--forbid must use IMPORTER:IMPORTED")
    return importer.strip(), imported.strip()


if __name__ == "__main__":
    raise SystemExit(main())
