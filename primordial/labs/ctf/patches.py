from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from collections.abc import Mapping
from typing import Any

from primordial.labs.ctf.hidden_material import reject_hidden_flag_material

ACCEPTED_STATUSES = {"accepted", "approved", "merged"}
PASS_STATUSES = {"pass", "passed"}
REVIEW_STATUSES = {"review", "review_required", "needs_review"}


@dataclass(frozen=True, slots=True)
class PatchProposal:
    id: str
    failure_analysis_id: str
    benchmark_run_id: str
    proposed_change: str
    files_changed: tuple[str, ...]
    tests_added: tuple[str, ...]
    validation_results: tuple[dict[str, str], ...]
    regression_results: tuple[dict[str, str], ...]
    hardcode_scan_result: dict[str, Any]
    status: str
    created_at: str = ""

    @classmethod
    def create(
        cls,
        *,
        id: str,
        failure_analysis_id: str,
        proposed_change: str,
        files_changed: list[str] | tuple[str, ...],
        tests_added: list[str] | tuple[str, ...],
        validation_results: list[Mapping[str, str]] | tuple[Mapping[str, str], ...],
        regression_results: list[Mapping[str, str]] | tuple[Mapping[str, str], ...],
        hardcode_scan_result: Mapping[str, Any],
        status: str,
        benchmark_run_id: str = "",
    ) -> PatchProposal:
        change = _required(proposed_change, "proposed_change")
        normalized_files = _text_tuple(files_changed)
        normalized_tests = _text_tuple(tests_added)
        validations = _result_tuple(validation_results)
        regressions = _result_tuple(regression_results)
        hardcode_scan = _hardcode_result_dict(hardcode_scan_result)
        normalized_status = _required(status, "status")
        payload = {
            "id": id,
            "failure_analysis_id": failure_analysis_id,
            "benchmark_run_id": benchmark_run_id,
            "proposed_change": change,
            "files_changed": normalized_files,
            "tests_added": normalized_tests,
            "validation_results": validations,
            "regression_results": regressions,
            "hardcode_scan_result": hardcode_scan,
            "status": normalized_status,
        }
        reject_hidden_flag_material(payload, path="patch_proposal", label="PatchProposal")
        _validate_acceptance(
            status=normalized_status,
            validation_results=validations,
            regression_results=regressions,
            hardcode_scan_result=hardcode_scan,
        )
        return cls(
            id=_required(id, "id"),
            failure_analysis_id=_required(failure_analysis_id, "failure_analysis_id"),
            benchmark_run_id=str(benchmark_run_id).strip(),
            proposed_change=change,
            files_changed=normalized_files,
            tests_added=normalized_tests,
            validation_results=validations,
            regression_results=regressions,
            hardcode_scan_result=hardcode_scan,
            status=normalized_status,
            created_at=datetime.now(UTC).isoformat(),
        )


def _required(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"PatchProposal requires {name}")
    return text


def _text_tuple(value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    return tuple(str(item).strip() for item in value if str(item).strip())


def _result_tuple(
    value: list[Mapping[str, str]] | tuple[Mapping[str, str], ...],
) -> tuple[dict[str, str], ...]:
    return tuple(_result_dict(item) for item in value)


def _result_dict(value: Mapping[str, str]) -> dict[str, str]:
    return {str(key): str(item) for key, item in dict(value).items()}


def _hardcode_result_dict(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in dict(value).items()}


def _validate_acceptance(
    *,
    status: str,
    validation_results: tuple[dict[str, str], ...],
    regression_results: tuple[dict[str, str], ...],
    hardcode_scan_result: dict[str, Any],
) -> None:
    normalized_status = status.strip().lower()
    if normalized_status not in ACCEPTED_STATUSES | REVIEW_STATUSES:
        return
    if not _has_passing_result(validation_results):
        raise ValueError("PatchProposal acceptance requires passing validation")
    if not _has_passing_result(regression_results):
        raise ValueError("PatchProposal acceptance requires passing regression results")
    if normalized_status in ACCEPTED_STATUSES and not _has_passing_hardcode_scan(hardcode_scan_result):
        raise ValueError("PatchProposal acceptance requires passing hardcode scan")
    if normalized_status in REVIEW_STATUSES and not _has_reviewable_hardcode_scan(hardcode_scan_result):
        raise ValueError("PatchProposal review requires review-only hardcode scan findings")


def _has_passing_result(results: tuple[dict[str, str], ...]) -> bool:
    return any(result.get("status", "").strip().lower() in PASS_STATUSES for result in results)


def _has_passing_hardcode_scan(hardcode_scan_result: Mapping[str, Any]) -> bool:
    findings = hardcode_scan_result.get("findings", ())
    return str(hardcode_scan_result.get("status", "")).strip().lower() in PASS_STATUSES and not findings


def _has_reviewable_hardcode_scan(hardcode_scan_result: Mapping[str, Any]) -> bool:
    scan_status = str(hardcode_scan_result.get("status", "")).strip().lower()
    findings = hardcode_scan_result.get("findings", ())
    if scan_status in PASS_STATUSES and not findings:
        return True
    if not isinstance(findings, (list, tuple)) or not findings:
        return False
    return all(_finding_severity(finding) == "review" for finding in findings)


def _finding_severity(finding: Any) -> str:
    if isinstance(finding, Mapping):
        return str(finding.get("severity", "")).strip().lower()
    return str(getattr(finding, "severity", "")).strip().lower()
