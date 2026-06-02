from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from primordial.core.domain.models import EvidenceRecord, Finding, Interest, Note, Target, utc_now
from primordial.core.sensitive_text import redact_sensitive_text


@dataclass(frozen=True, slots=True)
class TargetFindingsWorkspace:
    target_dir: Path
    guidance_path: Path
    findings_path: Path
    evidence_path: Path
    notion_export_path: Path

    def as_payload(self) -> dict[str, str]:
        return {
            "target_dir": str(self.target_dir),
            "guidance_path": str(self.guidance_path),
            "findings_path": str(self.findings_path),
            "evidence_path": str(self.evidence_path),
            "notion_export_path": str(self.notion_export_path),
        }


class FindingsContextService:
    def __init__(self, findings_dir: Path, notion_exports_dir: Path) -> None:
        self.findings_dir = findings_dir
        self.notion_exports_dir = notion_exports_dir

    def initialize(self) -> None:
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.notion_exports_dir.mkdir(parents=True, exist_ok=True)
        manifest = self.findings_dir / "workspace.yaml"
        if not manifest.exists():
            manifest.write_text(
                "id: primordial_findings_workspace\n"
                "authority: durable_operator_context\n"
                "prompt_ingestion: bounded_summaries_only\n"
                "paths:\n"
                "  guidance_path: targets/<target>/guidance.md\n"
                "  findings_path: targets/<target>/findings.md\n"
                "  evidence_path: targets/<target>/evidence.md\n"
                "  notion_export_path: notion/<target>/notion-export.md\n",
                encoding="utf-8",
            )

    def ensure_target(self, target: Target) -> TargetFindingsWorkspace:
        safe = self._safe_fragment(target.handle)
        target_dir = self.findings_dir / "targets" / safe
        notion_dir = self.notion_exports_dir / safe
        target_dir.mkdir(parents=True, exist_ok=True)
        notion_dir.mkdir(parents=True, exist_ok=True)
        workspace = TargetFindingsWorkspace(
            target_dir=target_dir,
            guidance_path=target_dir / "guidance.md",
            findings_path=target_dir / "findings.md",
            evidence_path=target_dir / "evidence.md",
            notion_export_path=notion_dir / "notion-export.md",
        )
        self._write_if_missing(
            workspace.guidance_path,
            f"# {self._redact_export_text(target.display_name)} Agent Guidance\n\n"
            "## AI Agent Guidance\n\n"
            "- Stay evidence-backed. Do not promote a finding without linked evidence.\n"
            "- Prefer narrow, scoped verification tasks over broad spray-and-pray actions.\n"
            "- Never run DoS or stress-style checks.\n"
            "- Record assumptions, blockers, and missing prerequisites explicitly.\n\n"
            "## Operator Notes\n\n"
            "- Add target-specific methodology guidance here.\n",
        )
        self._write_if_missing(
            workspace.findings_path,
            f"# {self._redact_export_text(target.display_name)} Findings\n\n"
            "No durable findings have been manually promoted yet.\n",
        )
        self._write_if_missing(
            workspace.evidence_path,
            f"# {self._redact_export_text(target.display_name)} Evidence Index\n\n"
            "Evidence index will be regenerated from local state.\n",
        )
        self._write_if_missing(
            workspace.notion_export_path,
            f"# {self._redact_export_text(target.display_name)} Notion Export\n\n"
            "Notion export mirror will be regenerated from local state.\n",
        )
        return workspace

    def sync_target_export(
        self,
        target: Target,
        *,
        evidence: list[EvidenceRecord],
        notes: list[Note],
        interests: list[Interest],
        findings: list[Finding],
    ) -> TargetFindingsWorkspace:
        workspace = self.ensure_target(target)
        self._write_evidence_index(workspace, target, evidence)
        export_lines = self._notion_export_lines(target, evidence, notes, interests, findings)
        workspace.notion_export_path.write_text("\n".join(export_lines).rstrip() + "\n", encoding="utf-8")
        return workspace

    def _write_evidence_index(
        self,
        workspace: TargetFindingsWorkspace,
        target: Target,
        evidence: list[EvidenceRecord],
    ) -> None:
        evidence_lines = [
            f"# {self._redact_export_text(target.display_name)} Evidence Index",
            "",
            f"Generated: {utc_now().isoformat()}",
            "",
        ]
        for item in evidence[:50]:
            evidence_lines.append(self._redact_export_text(f"- `{item.id}` {item.title}: {item.summary}"))
        workspace.evidence_path.write_text("\n".join(evidence_lines).rstrip() + "\n", encoding="utf-8")

    def _notion_export_lines(
        self,
        target: Target,
        evidence: list[EvidenceRecord],
        notes: list[Note],
        interests: list[Interest],
        findings: list[Finding],
    ) -> list[str]:
        export_lines = self._notion_export_header(target)
        self._extend_export_section(
            export_lines,
            "Observed Evidence",
            [self._redact_export_text(f"- `{item.id}` {item.title}: {item.summary}") for item in evidence[:25]],
            "- No evidence recorded.",
        )
        self._extend_export_section(
            export_lines,
            "Reviewed Findings",
            [self._redact_export_text(f"- `{finding.severity.value}` {finding.title}: {finding.summary}") for finding in findings[:25]],
            "- No reviewed findings recorded.",
        )
        self._extend_export_section(
            export_lines,
            "Operator Notes",
            [self._redact_export_text(f"- {note.title}: {note.body[:500]}") for note in notes[:25]],
            "- No operator notes recorded.",
        )
        self._extend_export_section(export_lines, "Candidate Tasks", [], "- No candidate tasks recorded.")
        self._extend_export_section(
            export_lines,
            "Hypotheses",
            [self._redact_export_text(f"- `{interest.status.value}` {interest.title}: {interest.summary}") for interest in interests[:25]],
            "- No open interests recorded.",
        )
        self._append_static_empty_export_sections(export_lines)
        return export_lines

    def _notion_export_header(self, target: Target) -> list[str]:
        return [
            f"# {self._redact_export_text(target.display_name)} Notion Export",
            "",
            "<!-- primordial-generated-export",
            "origin: generated_export",
            "ingest_allowed: false",
            "operational_retrieval_allowed: false",
            "-->",
            "",
            f"Target: `{self._redact_export_text(target.handle)}`",
            f"Profile: `{target.profile.value}`",
            f"Generated: {utc_now().isoformat()}",
            "",
            "## Authoritative Runtime State",
            "",
            f"- Target ID: `{target.id}`",
            f"- Target handle: `{self._redact_export_text(target.handle)}`",
            f"- Scope profile: `{target.profile.value}`",
            "- Active Operator Intent: managed by RuntimeStore.",
            "- Policy constraints: managed by PolicyEngine.",
            "",
            "## AI Agent Guidance",
            "",
            self._redact_export_text(self.read_guidance(target, max_chars=2400)) or "No target-specific guidance recorded.",
        ]

    def _redact_export_text(self, value: str) -> str:
        return redact_sensitive_text(value)

    def _extend_export_section(self, lines: list[str], title: str, rows: list[str], empty_message: str) -> None:
        lines.extend(["", f"## {title}", ""])
        lines.extend(rows or [empty_message])

    def _append_static_empty_export_sections(self, export_lines: list[str]) -> None:
        export_lines.extend(
            [
                "",
                "## AI Summaries",
                "",
                "- No cited AI summaries recorded.",
                "",
                "## RAG Advisory Material",
                "",
                "- No RAG advisory material recorded.",
                "",
                "## Blocked Actions",
                "",
                "- No blocked actions recorded.",
                "",
                "## CTFd Scoreboard Projection",
                "",
                "- No CTFd scoreboard projection recorded.",
                "",
                "## GitHub Links",
                "",
                "- No GitHub links recorded.",
                "",
                "## Sync Log / Conflicts",
                "",
                "- No sync conflicts recorded.",
            ]
        )

    def audit_generated_exports(self) -> dict[str, object]:
        records: list[dict[str, object]] = []
        for path in sorted(self.notion_exports_dir.glob("*/notion-export.md")):
            markers = self._generated_export_markers(path)
            missing = [
                name
                for name, expected in (
                    ("origin", "generated_export"),
                    ("ingest_allowed", "false"),
                    ("operational_retrieval_allowed", "false"),
                )
                if markers.get(name) != expected
            ]
            requires_quarantine = bool(missing)
            target_fragment = path.parent.name
            archive_path = self.notion_exports_dir / "_archive" / target_fragment / path.name
            records.append(
                {
                    "path": str(path),
                    "status": "requires_quarantine" if requires_quarantine else "ok",
                    "missing_metadata": missing,
                    "origin": markers.get("origin", ""),
                    "ingest_allowed": markers.get("ingest_allowed", ""),
                    "operational_retrieval_allowed": markers.get("operational_retrieval_allowed", ""),
                    "planned_action": "archive_quarantine" if requires_quarantine else "none",
                    "archive_path": str(archive_path) if requires_quarantine else "",
                    "quarantine_metadata": {
                        "origin": "generated_export",
                        "ingest_allowed": False,
                        "operational_retrieval_allowed": False,
                    }
                    if requires_quarantine
                    else {},
                }
            )
        return {
            "summary": {
                "files_seen": len(records),
                "quarantine_required": sum(1 for item in records if item["status"] == "requires_quarantine"),
            },
            "generated_exports": records,
        }

    def read_guidance(self, target: Target, *, max_chars: int = 4000) -> str:
        workspace = self.ensure_target(target)
        return self._bounded_read(workspace.guidance_path, max_chars=max_chars)

    def write_guidance(self, target: Target, body: str) -> TargetFindingsWorkspace:
        workspace = self.ensure_target(target)
        workspace.guidance_path.write_text(body.rstrip() + "\n", encoding="utf-8")
        return workspace

    def payload_for_target(self, target: Target, *, include_guidance: bool = False) -> dict[str, object]:
        workspace = self.ensure_target(target)
        payload: dict[str, object] = workspace.as_payload()
        if include_guidance:
            payload["guidance"] = self.read_guidance(target)
        return payload

    def context_digest(self, target: Target | None, *, max_chars: int = 3000) -> str:
        if target is None:
            return ""
        guidance = self._redact_export_text(self.read_guidance(target, max_chars=max_chars))
        if not guidance:
            return ""
        return f"Permanent findings guidance for {self._redact_export_text(target.handle)}:\n{guidance}"

    def _write_if_missing(self, path: Path, body: str) -> None:
        if not path.exists():
            path.write_text(body, encoding="utf-8")

    def _bounded_read(self, path: Path, *, max_chars: int) -> str:
        try:
            body = path.read_text(encoding="utf-8")
        except OSError:
            return ""
        body = body.strip()
        if len(body) <= max_chars:
            return body
        return body[:max_chars] + "\n...TRUNCATED_FINDINGS_CONTEXT..."

    def _safe_fragment(self, value: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip()).strip("._-")[:100] or "target"

    def _generated_export_markers(self, path: Path) -> dict[str, str]:
        body = self._bounded_read(path, max_chars=4096)
        markers: dict[str, str] = {}
        in_marker_block = False
        for line in body.splitlines():
            stripped = line.strip()
            if not in_marker_block:
                if not stripped:
                    continue
                if stripped == "<!-- primordial-generated-export":
                    in_marker_block = True
                    continue
                break
            if stripped == "-->":
                break
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            clean_key = key.strip().lower()
            if clean_key in {"origin", "ingest_allowed", "operational_retrieval_allowed"}:
                markers[clean_key] = value.strip().lower()
        return markers
