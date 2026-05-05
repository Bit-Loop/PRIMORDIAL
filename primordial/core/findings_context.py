from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from primordial.core.domain.models import EvidenceRecord, Finding, Interest, Note, Target, utc_now


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
        readme = self.findings_dir / "README.md"
        if not readme.exists():
            readme.write_text(
                "# Primordial Findings Workspace\n\n"
                "This folder is durable operator-facing context. Agents may read bounded summaries from target "
                "guidance files, but this folder is not loaded wholesale into model prompts.\n\n"
                "- `targets/<target>/guidance.md`: operator guidance for agents.\n"
                "- `targets/<target>/findings.md`: durable finding notes and manual observations.\n"
                "- `targets/<target>/evidence.md`: lightweight evidence index generated from local state.\n"
                "- `notion/<target>/notion-export.md`: local Notion-oriented export mirror.\n",
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
            f"# {target.display_name} Agent Guidance\n\n"
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
            f"# {target.display_name} Findings\n\n"
            "No durable findings have been manually promoted yet.\n",
        )
        self._write_if_missing(
            workspace.evidence_path,
            f"# {target.display_name} Evidence Index\n\n"
            "Evidence index will be regenerated from local state.\n",
        )
        self._write_if_missing(
            workspace.notion_export_path,
            f"# {target.display_name} Notion Export\n\n"
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
        evidence_lines = [
            f"# {target.display_name} Evidence Index",
            "",
            f"Generated: {utc_now().isoformat()}",
            "",
        ]
        for item in evidence[:50]:
            evidence_lines.append(f"- `{item.id}` {item.title}: {item.summary}")
        workspace.evidence_path.write_text("\n".join(evidence_lines).rstrip() + "\n", encoding="utf-8")

        export_lines = [
            f"# {target.display_name} Notion Export",
            "",
            f"Target: `{target.handle}`",
            f"Profile: `{target.profile.value}`",
            f"Generated: {utc_now().isoformat()}",
            "",
            "## AI Agent Guidance",
            "",
            self.read_guidance(target, max_chars=2400) or "No target-specific guidance recorded.",
            "",
            "## Findings",
            "",
        ]
        if findings:
            export_lines.extend(f"- `{finding.severity.value}` {finding.title}: {finding.summary}" for finding in findings[:25])
        else:
            export_lines.append("- No verified findings recorded.")
        export_lines.extend(["", "## Open Interests", ""])
        if interests:
            export_lines.extend(f"- `{interest.status.value}` {interest.title}: {interest.summary}" for interest in interests[:25])
        else:
            export_lines.append("- No open interests recorded.")
        export_lines.extend(["", "## Recent Notes", ""])
        if notes:
            export_lines.extend(f"- {note.title}: {note.body[:500]}" for note in notes[:25])
        else:
            export_lines.append("- No notes recorded.")
        export_lines.extend(["", "## Evidence References", ""])
        if evidence:
            export_lines.extend(f"- `{item.id}` {item.title}: {item.summary}" for item in evidence[:25])
        else:
            export_lines.append("- No evidence recorded.")
        workspace.notion_export_path.write_text("\n".join(export_lines).rstrip() + "\n", encoding="utf-8")
        return workspace

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
        guidance = self.read_guidance(target, max_chars=max_chars)
        if not guidance:
            return ""
        return f"Permanent findings guidance for {target.handle}:\n{guidance}"

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
