from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import re

from primordial.labs.ctf.hidden_material import reject_hidden_flag_material

TARGET_CONDITION_PATTERN = re.compile(r"\bif\s+target\s+(?:is|==)\b", re.IGNORECASE)
TERMINAL_SOLVE_STATUSES = frozenset({"blocked", "complete", "completed", "failed", "failure", "solved", "timeout"})
POSTMORTEM_MODES = frozenset({"postmortem", "postmortem_training", "training"})
WRITEUP_SOURCE_PREFIXES = ("solution:", "writeup:")
WRITEUP_SOURCE_MARKERS = frozenset({"solution", "solutions", "walkthrough", "writeup", "writeups"})
TARGET_SPECIFIC_MARKERS = frozenset(
    {
        "credential",
        "exact",
        "hardcode",
        "password",
        "route",
        "sequence",
        "username",
    }
)


@dataclass(frozen=True, slots=True)
class PostmortemRecord:
    id: str
    target_id: str
    solve_session_id: str
    solve_status: str
    mode: str
    source_refs: tuple[str, ...]
    lessons: tuple[str, ...]
    generalized_changes: tuple[str, ...]
    tests_added: tuple[str, ...]
    output_label: str
    created_at: str

    @classmethod
    def create(
        cls,
        *,
        id: str,
        target_id: str,
        solve_session_id: str,
        solve_status: str,
        mode: str,
        source_refs: list[str] | tuple[str, ...],
        lessons: list[str] | tuple[str, ...],
        generalized_changes: list[str] | tuple[str, ...],
        tests_added: list[str] | tuple[str, ...],
    ) -> PostmortemRecord:
        normalized_status = _normalized(solve_status)
        normalized_mode = _normalized(mode)
        normalized_source_refs = _text_tuple(source_refs, "source_refs")
        normalized_lessons = _text_tuple(lessons, "lessons")
        normalized_changes = _text_tuple(generalized_changes, "generalized_changes")
        normalized_tests = _text_tuple(tests_added, "tests_added")

        if _has_writeup_source(normalized_source_refs) and normalized_status not in TERMINAL_SOLVE_STATUSES:
            raise ValueError("writeup context requires completion or failure before postmortem use")
        if _has_writeup_source(normalized_source_refs) and normalized_mode not in POSTMORTEM_MODES:
            raise ValueError("writeup context requires postmortem mode")
        if not normalized_changes:
            raise ValueError("postmortem learned changes must include generalized changes")
        if not normalized_tests:
            raise ValueError("postmortem learned changes must include tests")

        payload = {
            "id": id,
            "target_id": target_id,
            "solve_session_id": solve_session_id,
            "solve_status": normalized_status,
            "mode": normalized_mode,
            "source_refs": normalized_source_refs,
            "lessons": normalized_lessons,
            "generalized_changes": normalized_changes,
            "tests_added": normalized_tests,
        }
        reject_hidden_flag_material(payload, path="postmortem_record", label="PostmortemRecord")
        _reject_target_specific_solution(target_id=target_id, values=normalized_lessons + normalized_changes)

        return cls(
            id=_required(id, "id"),
            target_id=_required(target_id, "target_id"),
            solve_session_id=_required(solve_session_id, "solve_session_id"),
            solve_status=normalized_status,
            mode=normalized_mode,
            source_refs=normalized_source_refs,
            lessons=normalized_lessons,
            generalized_changes=normalized_changes,
            tests_added=normalized_tests,
            output_label="postmortem/training",
            created_at=datetime.now(UTC).isoformat(),
        )


def _required(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"PostmortemRecord requires {name}")
    return text


def _text_tuple(value: list[str] | tuple[str, ...], name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"PostmortemRecord {name} must be a list or tuple")
    return tuple(str(item).strip() for item in value if str(item).strip())


def _normalized(value: str) -> str:
    return str(value).strip().lower().replace("-", "_").replace("/", "_").replace(" ", "_")


def _has_writeup_source(source_refs: tuple[str, ...]) -> bool:
    for source_ref in source_refs:
        lowered = source_ref.lower()
        if lowered.startswith(WRITEUP_SOURCE_PREFIXES):
            return True
        tokens = {token for token in re.split(r"[:/._-]+", lowered) if token}
        if tokens & WRITEUP_SOURCE_MARKERS:
            return True
    return False


def _reject_target_specific_solution(*, target_id: str, values: tuple[str, ...]) -> None:
    normalized_target = _normalized(target_id)
    for value in values:
        normalized_value = _normalized(value)
        if TARGET_CONDITION_PATTERN.search(value):
            raise ValueError("postmortem records must not encode target-specific solution logic")
        if normalized_target in normalized_value and any(marker in normalized_value for marker in TARGET_SPECIFIC_MARKERS):
            raise ValueError("postmortem records must not encode target-specific solution logic")
