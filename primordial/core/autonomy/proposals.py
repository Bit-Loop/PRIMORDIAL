from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True, frozen=True)
class GeneratedArtifact:
    path: Path
    description: str


@dataclass(slots=True, frozen=True)
class AutonomyProposal:
    kind: str
    title: str
    summary: str
    assumptions: list[str] = field(default_factory=list)
    risk_analysis: list[str] = field(default_factory=list)
    generated_artifacts: list[GeneratedArtifact] = field(default_factory=list)
    tests: list[str] = field(default_factory=list)
    promotion_requirements: list[str] = field(default_factory=list)

    def as_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "title": self.title,
            "summary": self.summary,
            "assumptions": list(self.assumptions),
            "risk_analysis": list(self.risk_analysis),
            "generated_artifacts": [
                {"path": str(item.path), "description": item.description}
                for item in self.generated_artifacts
            ],
            "tests": list(self.tests),
            "promotion_requirements": list(self.promotion_requirements),
        }
