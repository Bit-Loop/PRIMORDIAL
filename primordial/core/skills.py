from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(frozen=True, slots=True)
class RuntimeSkill:
    id: str
    title: str
    summary: str
    body: str
    path: str
    tags: tuple[str, ...] = ()

    def as_payload(self, *, include_body: bool = False) -> dict[str, object]:
        payload: dict[str, object] = {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "path": self.path,
            "tags": list(self.tags),
        }
        if include_body:
            payload["body"] = self.body
        return payload


class RuntimeSkillRegistry:
    def __init__(self, skills_dir: Path) -> None:
        self.skills_dir = skills_dir
        self._skills: dict[str, RuntimeSkill] = {}

    def initialize(self) -> None:
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        self.reload()

    def reload(self) -> list[RuntimeSkill]:
        loaded: dict[str, RuntimeSkill] = {}
        for path in self._skill_paths():
            skill = self._load_skill(path)
            loaded[skill.id] = skill
        self._skills = dict(sorted(loaded.items()))
        return list(self._skills.values())

    def list(self) -> list[RuntimeSkill]:
        return list(self._skills.values())

    def get(self, skill_id: str) -> RuntimeSkill | None:
        return self._skills.get(skill_id)

    def payload(self, *, include_body: bool = False) -> dict[str, object]:
        return {
            "skills_dir": str(self.skills_dir),
            "skills": [skill.as_payload(include_body=include_body) for skill in self.list()],
        }

    def context_digest(self, *, max_chars: int = 5000) -> str:
        lines: list[str] = []
        for skill in self.list():
            tags = f" tags={','.join(skill.tags)}" if skill.tags else ""
            lines.append(f"- {skill.id}: {skill.summary}{tags}")
        rendered = "\n".join(lines)
        if len(rendered) > max_chars:
            return rendered[:max_chars] + "\n...TRUNCATED_SKILL_DIGEST..."
        return rendered

    def _skill_paths(self) -> list[Path]:
        paths: list[Path] = []
        paths.extend(self.skills_dir.glob("*.md"))
        paths.extend(self.skills_dir.glob("*/SKILL.md"))
        return sorted({path.resolve() for path in paths if path.is_file()})

    def _load_skill(self, path: Path) -> RuntimeSkill:
        body = path.read_text(encoding="utf-8")
        metadata, content = self._split_frontmatter(body)
        default_name = path.parent.name if path.name == "SKILL.md" else path.stem
        title = metadata.get("title") or self._first_heading(content) or default_name
        skill_id = metadata.get("id") or self._safe_id(default_name)
        summary = metadata.get("summary") or self._first_paragraph(content) or title
        tags = tuple(
            item.strip()
            for item in str(metadata.get("tags", "")).split(",")
            if item.strip()
        )
        return RuntimeSkill(
            id=self._safe_id(skill_id),
            title=str(title).strip(),
            summary=str(summary).strip(),
            body=content.strip(),
            path=str(path),
            tags=tags,
        )

    def _split_frontmatter(self, body: str) -> tuple[dict[str, str], str]:
        if not body.startswith("---\n"):
            return {}, body
        _, rest = body.split("---\n", 1)
        if "---\n" not in rest:
            return {}, body
        raw_meta, content = rest.split("---\n", 1)
        metadata: dict[str, str] = {}
        for line in raw_meta.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            metadata[key.strip().lower()] = value.strip().strip('"')
        return metadata, content

    def _first_heading(self, body: str) -> str:
        for line in body.splitlines():
            if line.startswith("#"):
                return line.lstrip("#").strip()
        return ""

    def _first_paragraph(self, body: str) -> str:
        for chunk in re.split(r"\n\s*\n", body):
            text = " ".join(line.strip() for line in chunk.splitlines() if not line.startswith("#")).strip()
            if text:
                return text[:500]
        return ""

    def _safe_id(self, value: str) -> str:
        return re.sub(r"[^a-z0-9_.-]+", "-", value.strip().lower()).strip("-") or "skill"
