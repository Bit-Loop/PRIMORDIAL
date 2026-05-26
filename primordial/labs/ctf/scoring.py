from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


SOLVED_STATUSES = frozenset({"solved", "complete", "completed"})
REVIEW_STATUSES = frozenset({"review", "review_required", "needs_review"})
FAILED_STATUSES = frozenset({"fail", "failed", "no_solve", "error"})
SCORING_KEYS = ("targets_recorded", "solved", "review_required", "failed")


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


def is_scoring_counter(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _normalized(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")
