from __future__ import annotations

from dataclasses import dataclass, field

from primordial.core.context.source_types import NON_EVIDENCE_SOURCE_TYPES


EVIDENCE_KINDS = frozenset({"evidence"})
DISALLOWED_EVIDENCE_SOURCE_TYPES = NON_EVIDENCE_SOURCE_TYPES
DISALLOWED_EVIDENCE_CITATION_PREFIXES = ("rag:", "note:", "model:", "github:", "notion:", "ctfd:", "chat:")
DISALLOWED_FINDING_SOURCE_TYPES = DISALLOWED_EVIDENCE_SOURCE_TYPES
DISALLOWED_FINDING_CITATION_PREFIXES = ("rag:", "note:", "model:", "github:", "notion:", "ctfd:", "chat:")
TASK_METADATA_KINDS = frozenset({"task", "candidate_task", "task_metadata"})
PROMPT_RAW_CHAT_SOURCE_TYPES = frozenset({"chat"})
PROMPT_AI_DERIVED_KINDS = frozenset({"model_summary", "hypothesis", "candidate_task"})


@dataclass(slots=True)
class ContextSinkValidationResult:
    valid: bool
    accepted_refs: list[str] = field(default_factory=list)
    rejected_refs: list[str] = field(default_factory=list)
    quarantined_refs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_payload(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "accepted_refs": list(self.accepted_refs),
            "rejected_refs": list(self.rejected_refs),
            "quarantined_refs": list(self.quarantined_refs),
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }
