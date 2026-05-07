from __future__ import annotations

from pathlib import Path
import re

from primordial.core.autonomy.proposals import AutonomyProposal, GeneratedArtifact


class MethodologyCompiler:
    def __init__(self, proposals_root: Path) -> None:
        self.proposals_root = proposals_root

    def compile_markdown(self, markdown: str, *, name: str = "methodology") -> AutonomyProposal:
        title = self._first_heading(markdown) or name.replace("_", " ").title()
        if not markdown.strip():
            return AutonomyProposal(
                kind="investigation",
                title=title,
                summary="No methodology content was supplied.",
                assumptions=["Input markdown was empty."],
                risk_analysis=["No baseline catalog mutation was attempted."],
                tests=["Provide non-empty markdown and re-run compilation."],
                promotion_requirements=["Human review of methodology scope."],
            )
        slug = re.sub(r"[^a-z0-9_-]+", "_", name.lower()).strip("_") or "methodology"
        out_dir = self.proposals_root / slug
        artifact = out_dir / "proposal.md"
        return AutonomyProposal(
            kind="methodology",
            title=title,
            summary="Methodology input converted into a review proposal; baseline catalogs remain unchanged.",
            assumptions=["Markdown notes are operator-supplied and require review before promotion."],
            risk_analysis=["Generated artifacts are proposal-local and not executable by default."],
            generated_artifacts=[GeneratedArtifact(path=artifact, description="Compiled methodology proposal draft.")],
            tests=["Validate manifest schemas before any promotion.", "Run focused runtime tests for affected task kinds."],
            promotion_requirements=["Operator approval.", "Strict catalog validation.", "Evidence that generated helpers are unnecessary or safety-validated."],
        )

    def _first_heading(self, markdown: str) -> str | None:
        for line in markdown.splitlines():
            if line.startswith("#"):
                return line.lstrip("#").strip() or None
        return None
