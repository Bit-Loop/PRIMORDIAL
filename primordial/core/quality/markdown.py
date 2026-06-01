from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


QUARANTINE_PATH_PARTS = frozenset({"archive", "archives", "quarantine", "quarantined"})
GENERATED_MARKDOWN_PATH_PREFIXES = (
    "agent_chat_api/test-results/",
    "artifacts/model_eval/",
    "findings/notion/",
    "findings/targets/",
)
NON_SOURCE_MARKDOWN_PATH_PREFIXES = (
    ".pytest_cache/",
    ".venv/",
    "ENV/",
    "agent_chat_api/runtime/",
    "env/",
    "node_modules/",
    "primordial-rag-preprocess/.pytest_cache/",
    "primordial-rag-preprocess/output/",
    "runtime/",
    "venv/",
)
DENY_MARKERS = {
    "ingest_allowed": "false",
    "operational_retrieval_allowed": "false",
}
QUARANTINE_FRONT_MATTER = (
    "---\n"
    "origin: generated_export\n"
    "ingest_allowed: false\n"
    "operational_retrieval_allowed: false\n"
    "---\n\n"
)
QUARANTINE_MARKDOWN_ROOT = Path("runtime/quarantine/markdown")


@dataclass(frozen=True, slots=True)
class MarkdownAuditRecord:
    path: str
    status: str
    planned_action: str
    ingest_allowed: bool
    operational_retrieval_allowed: bool
    reason: str
    source_class: str
    quarantine_path: str


@dataclass(frozen=True, slots=True)
class MarkdownAudit:
    records: tuple[MarkdownAuditRecord, ...]
    summary: dict[str, int]

    def as_payload(self) -> dict[str, Any]:
        return {
            "summary": dict(self.summary),
            "records": [asdict(record) for record in self.records],
        }


def audit_markdown_sources(root: str | Path = ".") -> MarkdownAudit:
    repo_root = Path(root)
    records = tuple(_audit_path(repo_root, path) for path in _markdown_paths(repo_root))
    requires_action = sum(1 for record in records if record.planned_action != "none")
    quarantined = sum(1 for record in records if record.status == "quarantined")
    return MarkdownAudit(
        records=records,
        summary={
            "markdown_file_count": len(records),
            "tracked_markdown_count": len(records),
            "requires_action_count": requires_action,
            "quarantined_count": quarantined,
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit tracked Markdown source-of-truth risk.")
    parser.add_argument("--root", default=".", help="Repository root.")
    parser.add_argument("--json", help="Write audit JSON to this path.")
    parser.add_argument(
        "--apply-generated-quarantine",
        action="store_true",
        help="Move generated/historical Markdown outputs into runtime quarantine with deny metadata.",
    )
    parser.add_argument(
        "--quarantine-migrated-source",
        action="append",
        default=[],
        help="Move one migrated source Markdown file into runtime quarantine.",
    )
    parser.add_argument("--migration-ref", help="Typed/executable artifact that replaces migrated source Markdown.")
    args = parser.parse_args(argv)

    quarantine_payload: dict[str, Any] = {}
    if args.apply_generated_quarantine:
        quarantine_payload["generated"] = quarantine_generated_markdown(args.root)
    if args.quarantine_migrated_source:
        quarantine_payload["migrated_source"] = quarantine_migrated_markdown(
            args.root,
            paths=tuple(args.quarantine_migrated_source),
            migration_ref=args.migration_ref or "",
        )
    audit = audit_markdown_sources(args.root)
    payload = {"audit": audit.as_payload(), "quarantine": quarantine_payload} if quarantine_payload else audit.as_payload()
    body = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.json:
        Path(args.json).write_text(body, encoding="utf-8")
    else:
        print(body, end="")
    return 1 if audit.summary["requires_action_count"] else 0


def quarantine_generated_markdown(root: str | Path = ".") -> dict[str, Any]:
    repo_root = Path(root)
    audit = audit_markdown_sources(repo_root)
    records: list[dict[str, str]] = []
    for record in audit.records:
        if record.planned_action != "move_to_quarantine":
            continue
        source = repo_root / record.path
        destination = repo_root / record.quarantine_path
        if not source.is_file():
            records.append(
                {
                    "path": record.path,
                    "status": "skipped_missing_source",
                    "quarantine_path": record.quarantine_path,
                }
            )
            continue
        if destination.exists():
            raise FileExistsError(f"quarantine destination already exists: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        body = source.read_text(encoding="utf-8")
        source.replace(destination)
        destination.write_text(_with_quarantine_front_matter(body), encoding="utf-8")
        records.append(
            {
                "path": record.path,
                "status": "quarantined",
                "quarantine_path": record.quarantine_path,
            }
        )
    return {
        "summary": {
            "quarantined_count": sum(1 for item in records if item["status"] == "quarantined"),
            "skipped_count": sum(1 for item in records if item["status"].startswith("skipped_")),
        },
        "records": records,
    }


def quarantine_migrated_markdown(
    root: str | Path = ".",
    *,
    paths: tuple[str, ...],
    migration_ref: str,
) -> dict[str, Any]:
    if not migration_ref.strip():
        raise ValueError("migration_ref is required for migrated source Markdown quarantine")
    repo_root = Path(root)
    records: list[dict[str, str]] = []
    for rel_path in paths:
        if Path(rel_path).suffix.lower() != ".md":
            raise ValueError(f"migrated source must be Markdown: {rel_path}")
        source = repo_root / rel_path
        destination = repo_root / QUARANTINE_MARKDOWN_ROOT / rel_path
        if not source.is_file():
            records.append(
                {
                    "path": rel_path,
                    "status": "skipped_missing_source",
                    "quarantine_path": str(QUARANTINE_MARKDOWN_ROOT / rel_path),
                }
            )
            continue
        if destination.exists():
            raise FileExistsError(f"quarantine destination already exists: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        body = source.read_text(encoding="utf-8")
        source.replace(destination)
        destination.write_text(_with_migrated_front_matter(body, migration_ref=migration_ref), encoding="utf-8")
        records.append(
            {
                "path": rel_path,
                "status": "quarantined",
                "quarantine_path": str(QUARANTINE_MARKDOWN_ROOT / rel_path),
                "migration_ref": migration_ref,
            }
        )
    return {
        "summary": {
            "quarantined_count": sum(1 for item in records if item["status"] == "quarantined"),
            "skipped_count": sum(1 for item in records if item["status"].startswith("skipped_")),
        },
        "records": records,
    }


def _audit_path(root: Path, rel_path: str) -> MarkdownAuditRecord:
    path = root / rel_path
    markers = _front_matter_markers(path)
    marker_denies = all(markers.get(key, "").lower() == value for key, value in DENY_MARKERS.items())
    quarantined_path = bool(set(Path(rel_path).parts) & QUARANTINE_PATH_PARTS)
    if quarantined_path and marker_denies:
        return MarkdownAuditRecord(
            path=rel_path,
            status="quarantined",
            planned_action="none",
            ingest_allowed=False,
            operational_retrieval_allowed=False,
            reason="tracked Markdown is in a quarantine/archive path with deny markers",
            source_class=markers.get("origin", "quarantined"),
            quarantine_path="",
        )
    if _is_generated_markdown_path(rel_path):
        return MarkdownAuditRecord(
            path=rel_path,
            status="requires_generated_quarantine",
            planned_action="move_to_quarantine",
            ingest_allowed=False,
            operational_retrieval_allowed=False,
            reason="generated or historical Markdown output must move to quarantine with deny metadata",
            source_class="generated_export",
            quarantine_path=str(QUARANTINE_MARKDOWN_ROOT / rel_path),
        )
    return MarkdownAuditRecord(
        path=rel_path,
        status="requires_migration_or_quarantine",
        planned_action="archive_quarantine",
        ingest_allowed=False,
        operational_retrieval_allowed=False,
        reason="tracked Markdown must not remain source-of-truth material",
        source_class="source_markdown",
        quarantine_path="",
    )


def _markdown_paths(root: Path) -> tuple[str, ...]:
    paths = set(_git_paths(root, ["ls-files", "--cached", "*.md"]))
    paths.update(
        path
        for path in _git_paths(root, ["ls-files", "--others", "--exclude-standard", "*.md"])
        if not _is_non_source_markdown_path(path)
    )
    paths.update(
        path
        for path in _git_paths(root, ["ls-files", "--others", "--ignored", "--exclude-standard", "*.md"])
        if not _is_non_source_markdown_path(path)
    )
    return tuple(sorted(path for path in paths if (root / path).is_file()))


def _git_paths(root: Path, args: list[str]) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(f"could not list Markdown files: {result.stderr.strip()}")
    return tuple(sorted(line.strip() for line in result.stdout.splitlines() if line.strip()))


def _front_matter_markers(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return {}
    if not lines or lines[0].strip() != "---":
        return {}
    markers: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        key, separator, value = line.partition(":")
        if separator:
            markers[key.strip()] = value.strip()
    return markers


def _is_generated_markdown_path(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/")
    return any(normalized.startswith(prefix) for prefix in GENERATED_MARKDOWN_PATH_PREFIXES)


def _is_non_source_markdown_path(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/")
    return any(normalized.startswith(prefix) for prefix in NON_SOURCE_MARKDOWN_PATH_PREFIXES)


def _with_quarantine_front_matter(body: str) -> str:
    markers = _front_matter_markers_from_text(body)
    has_deny_markers = all(markers.get(key, "").lower() == value for key, value in DENY_MARKERS.items())
    if markers.get("origin", "").lower() == "generated_export" and has_deny_markers:
        return body
    return QUARANTINE_FRONT_MATTER + body.lstrip("\n")


def _with_migrated_front_matter(body: str, *, migration_ref: str) -> str:
    markers = _front_matter_markers_from_text(body)
    has_deny_markers = all(markers.get(key, "").lower() == value for key, value in DENY_MARKERS.items())
    if markers.get("origin", "").lower() == "source_markdown" and markers.get("migration_ref") == migration_ref and has_deny_markers:
        return body
    return (
        "---\n"
        "origin: source_markdown\n"
        f"migration_ref: {migration_ref}\n"
        "ingest_allowed: false\n"
        "operational_retrieval_allowed: false\n"
        "---\n\n"
        + body.lstrip("\n")
    )


def _front_matter_markers_from_text(body: str) -> dict[str, str]:
    lines = body.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    markers: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        key, separator, value = line.partition(":")
        if separator:
            markers[key.strip()] = value.strip()
    return markers


if __name__ == "__main__":
    raise SystemExit(main())
