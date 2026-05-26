from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from primordial.labs.ctf.hidden_material import reject_hidden_flag_material


@dataclass(frozen=True, slots=True)
class FailureAnalysis:
    id: str
    solve_session_id: str
    failure_class: str
    related_evidence: tuple[str, ...]
    related_policy_decisions: tuple[str, ...]
    related_model_runs: tuple[str, ...]
    suspected_root_cause: str
    proposed_fix: str
    github_issue_id: str = ""
    created_at: str = ""

    @classmethod
    def create(
        cls,
        *,
        id: str,
        solve_session_id: str,
        failure_class: str,
        related_evidence: list[str] | tuple[str, ...],
        related_policy_decisions: list[str] | tuple[str, ...],
        related_model_runs: list[str] | tuple[str, ...],
        suspected_root_cause: str,
        proposed_fix: str,
        github_issue_id: str = "",
    ) -> FailureAnalysis:
        root_cause = _required(suspected_root_cause, "suspected_root_cause")
        fix = _required(proposed_fix, "proposed_fix")
        payload = {
            "id": id,
            "solve_session_id": solve_session_id,
            "failure_class": failure_class,
            "related_evidence": tuple(related_evidence),
            "related_policy_decisions": tuple(related_policy_decisions),
            "related_model_runs": tuple(related_model_runs),
            "suspected_root_cause": root_cause,
            "proposed_fix": fix,
            "github_issue_id": github_issue_id,
        }
        reject_hidden_flag_material(payload, path="failure_analysis", label="FailureAnalysis")
        return cls(
            id=_required(id, "id"),
            solve_session_id=_required(solve_session_id, "solve_session_id"),
            failure_class=_required(failure_class, "failure_class"),
            related_evidence=_text_tuple(related_evidence),
            related_policy_decisions=_text_tuple(related_policy_decisions),
            related_model_runs=_text_tuple(related_model_runs),
            suspected_root_cause=root_cause,
            proposed_fix=fix,
            github_issue_id=str(github_issue_id).strip(),
            created_at=datetime.now(UTC).isoformat(),
        )


def _required(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"FailureAnalysis requires {name}")
    return text


def _text_tuple(value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    return tuple(str(item).strip() for item in value if str(item).strip())
