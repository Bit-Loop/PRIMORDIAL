from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from primordial.labs.ctf.hidden_material import reject_hidden_flag_material
from primordial.labs.ctf.scoring import (
    REVIEW_STATUSES,
    SCORING_KEYS,
    SOLVED_STATUSES,
    compute_scoring_summary,
    is_scoring_counter,
)


CLOSED_BOOK_MODES = frozenset({"closed_book", "closed-book", "closed book"})
HIDDEN_SOLUTION_AVAILABLE = frozenset({"available_to_agent", "agent_access", "available", "exposed"})
FORBIDDEN_ACTIVE_SOURCE_REF_MARKERS = ("writeup", "solution", "postmortem")
PASS_HARDCODE_SCAN_STATUSES = frozenset({"pass", "passed"})
REVIEW_HARDCODE_SEVERITIES = frozenset({"review"})


@dataclass(frozen=True, slots=True)
class BenchmarkRun:
    id: str
    target_set: tuple[str, ...]
    benchmark_mode: str
    mutation_seed: str
    code_version: str
    policy_version: str
    model_versions: Mapping[str, str] = field(default_factory=dict)
    started_at: str = ""
    ended_at: str = ""
    solve_results: tuple[dict[str, Any], ...] = ()
    scoring_summary: Mapping[str, Any] = field(default_factory=dict)
    hidden_solution_access_status: str = ""
    hardcode_scan_result: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def start(
        cls,
        *,
        id: str,
        target_set: list[str] | tuple[str, ...],
        benchmark_mode: str,
        mutation_seed: str,
        code_version: str,
        policy_version: str,
        model_versions: Mapping[str, str],
        hidden_solution_access_status: str,
        hardcode_scan_result: Mapping[str, Any],
    ) -> BenchmarkRun:
        mode = _required(benchmark_mode, "benchmark_mode")
        hidden_status = _required(hidden_solution_access_status, "hidden_solution_access_status")
        targets = _target_set_tuple(target_set)
        model_version_map = _model_versions_dict(model_versions)
        hardcode_scan = _mapping_dict(hardcode_scan_result, "hardcode scan result")
        payload = {
            "id": id,
            "target_set": targets,
            "benchmark_mode": mode,
            "mutation_seed": mutation_seed,
            "code_version": code_version,
            "policy_version": policy_version,
            "model_versions": model_version_map,
            "hidden_solution_access_status": hidden_status,
            "hardcode_scan_result": hardcode_scan,
        }
        reject_hidden_flag_material(payload, path="benchmark_run", label="BenchmarkRun")
        if _normalized(mode) in CLOSED_BOOK_MODES and _normalized(hidden_status) in HIDDEN_SOLUTION_AVAILABLE:
            raise ValueError("closed-book BenchmarkRun must not expose hidden solution material to the agent")
        return cls(
            id=_required(id, "id"),
            target_set=targets,
            benchmark_mode=mode,
            mutation_seed=_required(mutation_seed, "mutation_seed"),
            code_version=_required(code_version, "code_version"),
            policy_version=_required(policy_version, "policy_version"),
            model_versions=model_version_map,
            hidden_solution_access_status=hidden_status,
            hardcode_scan_result=hardcode_scan,
            started_at=_now_iso(),
        )

    def record_solve_result(
        self,
        *,
        solve_session_id: str,
        target_id: str,
        solve_status: str,
        result: str,
        evidence_ids: list[str] | tuple[str, ...],
        policy_decision_ids: list[str] | tuple[str, ...],
        hardcode_scan_result: Mapping[str, Any],
        source_refs: list[str] | tuple[str, ...] = (),
    ) -> BenchmarkRun:
        if self.ended_at:
            raise ValueError("BenchmarkRun finalized runs cannot record additional solve results")
        evidence_refs = _ref_tuple(
            evidence_ids,
            "evidence_ids",
            allow_empty=True,
            required_prefix="evidence:",
            reject_duplicates=True,
        )
        target_ref = _required(target_id, "target_id")
        if target_ref not in self.target_set:
            raise ValueError(f"BenchmarkRun target_id must be in target_set: {target_ref}")
        if target_ref in _recorded_target_ids(self.solve_results):
            raise ValueError(f"BenchmarkRun duplicate target result: {target_ref}")
        normalized_status = _normalized(solve_status)
        source_ref_tuple = _ref_tuple(source_refs, "source_refs", allow_empty=True, reject_duplicates=True)
        if normalized_status in SOLVED_STATUSES and not evidence_refs:
            raise ValueError("solved BenchmarkRun result requires supporting evidence")
        if _normalized(self.benchmark_mode) in CLOSED_BOOK_MODES:
            _validate_closed_book_source_refs(source_ref_tuple, require_refs=normalized_status in SOLVED_STATUSES)
        solve_result = {
            "solve_session_id": _required(solve_session_id, "solve_session_id"),
            "target_id": target_ref,
            "solve_status": _required(solve_status, "solve_status"),
            "result": _required(result, "result"),
            "evidence_ids": evidence_refs,
            "source_refs": source_ref_tuple,
            "policy_decision_ids": _ref_tuple(
                policy_decision_ids,
                "policy_decision_ids",
                allow_empty=True,
                required_prefix="policy:",
            ),
            "hardcode_scan_result": _mapping_dict(hardcode_scan_result, "hardcode scan result"),
        }
        reject_hidden_flag_material(solve_result, path="benchmark_run.solve_result", label="BenchmarkRun")
        return replace(self, solve_results=self.solve_results + (solve_result,))

    def with_scoring_summary(self, scoring_summary: Mapping[str, Any]) -> BenchmarkRun:
        if self.ended_at:
            raise ValueError("BenchmarkRun finalized runs cannot update scoring summary")
        if not isinstance(scoring_summary, Mapping):
            raise ValueError("BenchmarkRun scoring summary malformed")
        _validate_scored_solve_hardcode_scans(self.solve_results)
        extra_summary = dict(scoring_summary)
        computed_overrides = tuple(key for key in SCORING_KEYS if key in extra_summary)
        if computed_overrides:
            raise ValueError(
                "BenchmarkRun computed scoring keys cannot be overridden: "
                + ", ".join(computed_overrides)
            )
        invalid_values = tuple(
            f"{key}={value}" for key, value in extra_summary.items() if not is_scoring_counter(value)
        )
        if invalid_values:
            raise ValueError(
                "BenchmarkRun scoring summary value must be a non-negative integer: "
                + ", ".join(invalid_values)
            )
        summary = compute_scoring_summary(self.solve_results)
        summary.update(extra_summary)
        return replace(self, scoring_summary=summary, ended_at=_now_iso())


def _required(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"BenchmarkRun requires {name}")
    return text


def _text_tuple(
    value: list[str] | tuple[str, ...],
    name: str,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"BenchmarkRun {name} malformed")
    refs = tuple(str(item).strip() for item in value if str(item).strip())
    if not refs and not allow_empty:
        raise ValueError(f"BenchmarkRun requires {name}")
    return refs


def _ref_tuple(
    value: list[str] | tuple[str, ...],
    name: str,
    *,
    allow_empty: bool = False,
    required_prefix: str = "",
    reject_duplicates: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"BenchmarkRun {name} malformed")
    refs: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"BenchmarkRun {name} entry requires non-empty text")
        ref = item.strip()
        if required_prefix and not ref.startswith(required_prefix):
            raise ValueError(f"BenchmarkRun {name} entry must use {required_prefix}<id>")
        if reject_duplicates and ref in refs:
            raise ValueError(f"BenchmarkRun duplicate {name} entry: {ref}")
        refs.append(ref)
    if not refs and not allow_empty:
        raise ValueError(f"BenchmarkRun requires {name}")
    return tuple(refs)


def _target_set_tuple(value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    targets = _ref_tuple(value, "target_set")
    seen: set[str] = set()
    for target_id in targets:
        if target_id in seen:
            raise ValueError(f"BenchmarkRun duplicate target_set entry: {target_id}")
        seen.add(target_id)
    return targets


def _recorded_target_ids(solve_results: tuple[dict[str, Any], ...]) -> set[str]:
    return {
        str(solve_result.get("target_id", "")).strip()
        for solve_result in solve_results
        if str(solve_result.get("target_id", "")).strip()
    }


def _validate_closed_book_source_refs(source_refs: tuple[str, ...], *, require_refs: bool) -> None:
    if require_refs and not source_refs:
        raise ValueError("closed-book solved BenchmarkRun result requires source_refs")
    for source_ref in source_refs:
        if _is_forbidden_active_source_ref(source_ref):
            raise ValueError("closed-book BenchmarkRun result must not use writeup/postmortem source_refs")


def _is_forbidden_active_source_ref(source_ref: str) -> bool:
    normalized = _normalized(source_ref).replace(":", "_").replace("/", "_")
    return any(marker in normalized for marker in FORBIDDEN_ACTIVE_SOURCE_REF_MARKERS)


def _mapping_dict(value: Mapping[str, Any], name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"BenchmarkRun {name} malformed")
    return dict(value)


def _validate_scored_solve_hardcode_scans(solve_results: tuple[dict[str, Any], ...]) -> None:
    for solve_result in solve_results:
        status = _normalized(solve_result.get("solve_status", ""))
        result = _normalized(solve_result.get("result", ""))
        scan = solve_result.get("hardcode_scan_result", {})
        if status in SOLVED_STATUSES or result in SOLVED_STATUSES:
            if not _clean_hardcode_scan(scan):
                raise ValueError("solved BenchmarkRun result requires passing hardcode scan")
        elif status in REVIEW_STATUSES or result in REVIEW_STATUSES:
            if not _review_only_hardcode_scan(scan):
                raise ValueError("review BenchmarkRun result requires review-only hardcode scan findings")


def _clean_hardcode_scan(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    findings = value.get("findings", ())
    return _normalized(value.get("status", "")) in PASS_HARDCODE_SCAN_STATUSES and not findings


def _review_only_hardcode_scan(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    findings = value.get("findings", ())
    if not isinstance(findings, (list, tuple)) or not findings:
        return False
    return all(_finding_severity(finding) in REVIEW_HARDCODE_SEVERITIES for finding in findings)


def _finding_severity(finding: Any) -> str:
    if isinstance(finding, Mapping):
        return _normalized(finding.get("severity", ""))
    return _normalized(getattr(finding, "severity", ""))


def _model_versions_dict(value: Mapping[str, str]) -> dict[str, str]:
    model_versions = _mapping_dict(value, "model versions")
    for role, version in model_versions.items():
        if not isinstance(role, str) or not role.strip():
            raise ValueError("BenchmarkRun model versions entry requires non-empty text role")
        if not isinstance(version, str) or not version.strip():
            raise ValueError("BenchmarkRun model versions entry requires non-empty text version")
    return model_versions


def _normalized(value: str) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()
