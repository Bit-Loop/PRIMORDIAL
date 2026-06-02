from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from primordial.labs.ctf.benchmark import HIDDEN_SOLUTION_AVAILABLE
from primordial.labs.ctf.sessions import SOLVED_STATUSES, SolveSession


PASS_STATUSES = frozenset({"pass", "passed"})


@dataclass(frozen=True, slots=True)
class SolveVerificationResult:
    status: str
    errors: tuple[str, ...]


class SolveVerifier:
    @staticmethod
    def verify(
        *,
        session: SolveSession,
        hardcode_scan_result: Mapping[str, Any],
        hidden_solution_access_status: str,
    ) -> SolveVerificationResult:
        errors: list[str] = []
        if _normalized(session.solve_status) not in SOLVED_STATUSES:
            errors.append("solved status")
        if not session.actions:
            errors.append("action trace")
        if not session.evidence_ids:
            errors.append("supporting evidence")
        if not _has_allowed_policy_decision(session):
            errors.append("allowed policy decision")
        if _has_unapproved_flag_submission(session):
            errors.append("allowed flag submission policy decision")
        if _has_hard_fail_finding(hardcode_scan_result):
            errors.append("passing hardcode scan")
        review_required = _has_review_finding(hardcode_scan_result)
        if _normalized(hidden_solution_access_status) in HIDDEN_SOLUTION_AVAILABLE:
            errors.append("hidden solution material")
        if errors:
            return SolveVerificationResult(status="fail", errors=tuple(errors))
        if review_required:
            return SolveVerificationResult(status="review", errors=("hardcode review finding",))
        return SolveVerificationResult(status="pass", errors=())


def _has_allowed_policy_decision(session: SolveSession) -> bool:
    return any(
        _normalized(str(decision.get("decision", ""))) in {"allow", "allowed"}
        for decision in session.policy_decisions
    )


def _has_unapproved_flag_submission(session: SolveSession) -> bool:
    allowed_policy_ids = {
        str(decision.get("decision_id", "")).strip()
        for decision in session.policy_decisions
        if _normalized(str(decision.get("decision", ""))) in {"allow", "allowed"}
    }
    for action in session.actions:
        if _normalized(str(action.get("action_type", ""))) != "ctfd_flag_submission":
            continue
        metadata = action.get("metadata", {})
        if not isinstance(metadata, Mapping):
            return True
        policy_decision_id = str(metadata.get("policy_decision_id", "")).strip()
        if not policy_decision_id or policy_decision_id not in allowed_policy_ids:
            return True
    return False


def _scan_status(value: Mapping[str, Any]) -> str:
    return _normalized(str(dict(value).get("status", "")))


def _has_hard_fail_finding(value: Mapping[str, Any]) -> bool:
    if not isinstance(value, Mapping):
        return True
    findings = tuple(dict(value).get("findings", ()))
    if _scan_status(value) in PASS_STATUSES and not findings:
        return False
    if not findings:
        return True
    return any(_finding_severity(finding) != "review" for finding in findings)


def _has_review_finding(value: Mapping[str, Any]) -> bool:
    if not isinstance(value, Mapping):
        return False
    return any(_finding_severity(finding) == "review" for finding in tuple(dict(value).get("findings", ())))


def _finding_severity(finding: Any) -> str:
    if isinstance(finding, Mapping):
        return _normalized(str(finding.get("severity", "")))
    return _normalized(str(getattr(finding, "severity", "")))


def _normalized(value: str) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")
