from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from primordial.labs.ctf.hidden_material import reject_hidden_flag_material


SOLVED_STATUSES = frozenset({"solved", "complete", "completed"})
REVIEW_STATUSES = frozenset({"review", "review_required", "needs_review"})
FAILED_STATUSES = frozenset({"fail", "failed", "no_solve", "error"})
SCORING_KEYS = ("targets_recorded", "solved", "review_required", "failed")
SCORING_EVIDENCE_EXIT_GATES = ("scoring_results_include_evidence_refs",)


@dataclass(frozen=True, slots=True)
class ScoringEvidenceResult:
    target_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    scoring_summary: dict[str, int]
    exit_gates: tuple[str, ...]

    def as_payload(self) -> dict[str, Any]:
        return {
            "target_ids": list(self.target_ids),
            "evidence_refs": list(self.evidence_refs),
            "scoring_summary": dict(self.scoring_summary),
            "exit_gates": list(self.exit_gates),
        }


def compute_scoring_summary(solve_results: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    summary = {
        "targets_recorded": 0,
        "solved": 0,
        "review_required": 0,
        "failed": 0,
    }
    for solve_result in solve_results:
        summary["targets_recorded"] += 1
        status = _normalized(solve_result.get("solve_status", ""))
        result = _normalized(solve_result.get("result", ""))
        if status in SOLVED_STATUSES or result in SOLVED_STATUSES:
            summary["solved"] += 1
        elif status in REVIEW_STATUSES or result in REVIEW_STATUSES:
            summary["review_required"] += 1
        elif status in FAILED_STATUSES or result in FAILED_STATUSES:
            summary["failed"] += 1
    return summary


def validate_scoring_results_evidence_refs(
    solve_results: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    *,
    target_ids: list[str] | tuple[str, ...] = (),
) -> ScoringEvidenceResult:
    if not isinstance(solve_results, (list, tuple)):
        raise ValueError("CTF scoring evidence solve_results must be a list or tuple")
    if not solve_results:
        raise ValueError("CTF scoring evidence requires solve_results")
    checked_targets = _target_ids(target_ids)
    payload = {"solve_results": list(solve_results), "target_ids": checked_targets}
    reject_hidden_flag_material(payload, path="ctf_scoring_evidence", label="ScoringEvidenceResult")

    result_targets: list[str] = []
    evidence_refs: list[str] = []
    checked_results: list[dict[str, Any]] = []
    for index, solve_result in enumerate(solve_results):
        result = _solve_result_mapping(solve_result, index=index)
        target_id = _required_text(result.get("target_id"), f"solve_results[{index}].target_id")
        if checked_targets and target_id not in checked_targets:
            raise ValueError(f"CTF scoring evidence target_id is outside phase target set: {target_id}")
        if target_id in result_targets:
            raise ValueError(f"CTF scoring evidence duplicate target result: {target_id}")
        result_targets.append(target_id)
        refs = _evidence_refs(result.get("evidence_ids"), source=f"solve_results[{index}].evidence_ids")
        evidence_refs.extend(ref for ref in refs if ref not in evidence_refs)
        checked_results.append(result)
    if checked_targets:
        missing = tuple(target_id for target_id in checked_targets if target_id not in result_targets)
        if missing:
            raise ValueError("CTF scoring evidence missing target result: " + ", ".join(missing))
        ordered_targets = checked_targets
    else:
        ordered_targets = tuple(result_targets)
    return ScoringEvidenceResult(
        target_ids=ordered_targets,
        evidence_refs=tuple(evidence_refs),
        scoring_summary=compute_scoring_summary(checked_results),
        exit_gates=SCORING_EVIDENCE_EXIT_GATES,
    )


def is_scoring_counter(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _target_ids(value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("CTF scoring evidence target_ids must be a list or tuple")
    targets: list[str] = []
    for item in value:
        target_id = _required_text(item, "target_ids entry")
        if target_id in targets:
            raise ValueError(f"CTF scoring evidence duplicate target_ids entry: {target_id}")
        targets.append(target_id)
    return tuple(targets)


def _solve_result_mapping(value: Mapping[str, Any], *, index: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"CTF scoring evidence solve_results[{index}] must be an object")
    return dict(value)


def _evidence_refs(value: Any, *, source: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"CTF scoring evidence {source} must be a list or tuple")
    refs: list[str] = []
    for item in value:
        ref = _required_text(item, f"{source} entry")
        if not ref.startswith("evidence:"):
            raise ValueError(f"CTF scoring evidence {source} entry must use evidence:<id>")
        if ref in refs:
            raise ValueError(f"CTF scoring evidence duplicate {source} entry: {ref}")
        refs.append(ref)
    if not refs:
        raise ValueError(f"CTF scoring evidence requires {source}")
    return tuple(refs)


def _required_text(value: Any, source: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"CTF scoring evidence requires {source}")
    return text


def _normalized(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")
