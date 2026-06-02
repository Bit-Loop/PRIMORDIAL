from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from primordial.labs.ctf.benchmark import BenchmarkRun
from primordial.labs.ctf.failures import FailureAnalysis
from primordial.labs.ctf.patches import PatchProposal
from primordial.labs.ctf.scoring import SCORING_KEYS, compute_scoring_summary, is_scoring_counter


PASS_HARDCODE_SCAN_STATUSES = frozenset({"pass", "passed"})
SKIPPED_HARDCODE_SCAN_STATUSES = frozenset({"not_run", "not run", "skipped"})
REVIEW_HARDCODE_SEVERITIES = frozenset({"review"})
HARD_FAIL_HARDCODE_SEVERITIES = frozenset({"hard_fail", "hard fail", "hard-fail"})
CLOSED_BOOK_MODES = frozenset({"closed_book", "closed-book", "closed book"})
FORBIDDEN_ACTIVE_SOURCE_REF_MARKERS = ("writeup", "solution", "postmortem")


@dataclass(frozen=True, slots=True)
class CTFIntegrityResult:
    status: str
    errors: tuple[str, ...]


class CTFHarnessIntegrity:
    @staticmethod
    def validate_patch_proposal(
        proposal: PatchProposal,
        *,
        failure_analysis_ids: Iterable[str],
        benchmark_run_ids: Iterable[str],
    ) -> CTFIntegrityResult:
        errors: list[str] = []
        known_failures = _text_set(failure_analysis_ids)
        known_benchmarks = _text_set(benchmark_run_ids)
        if proposal.failure_analysis_id not in known_failures:
            errors.append(f"unresolved failure_analysis_id: {proposal.failure_analysis_id}")
        if proposal.benchmark_run_id and proposal.benchmark_run_id not in known_benchmarks:
            errors.append(f"unresolved benchmark_run_id: {proposal.benchmark_run_id}")
        return CTFIntegrityResult(status="fail" if errors else "pass", errors=tuple(errors))

    @staticmethod
    def validate_failure_analysis(
        analysis: FailureAnalysis,
        *,
        solve_session_ids: Iterable[str],
        evidence_ids: Iterable[str],
        policy_decision_ids: Iterable[str],
        model_run_ids: Iterable[str],
    ) -> CTFIntegrityResult:
        errors: list[str] = []
        known_sessions = _text_set(solve_session_ids)
        known_evidence = _text_set(evidence_ids)
        known_policies = _text_set(policy_decision_ids)
        known_models = _text_set(model_run_ids)
        if analysis.solve_session_id not in known_sessions:
            errors.append(f"unresolved solve_session_id: {analysis.solve_session_id}")
        errors.extend(_unresolved("evidence_id", analysis.related_evidence, known_evidence))
        errors.extend(_unresolved("policy_decision_id", analysis.related_policy_decisions, known_policies))
        errors.extend(_unresolved("model_run_id", analysis.related_model_runs, known_models))
        return CTFIntegrityResult(status="fail" if errors else "pass", errors=tuple(errors))

    @staticmethod
    def validate_benchmark_run(
        run: BenchmarkRun,
        *,
        solve_session_ids: Iterable[str],
        target_ids: Iterable[str],
        evidence_ids: Iterable[str],
        policy_decision_ids: Iterable[str],
    ) -> CTFIntegrityResult:
        errors: list[str] = []
        known_sessions = _text_set(solve_session_ids)
        known_targets = _text_set(target_ids)
        known_evidence = _text_set(evidence_ids)
        known_policies = _text_set(policy_decision_ids)
        errors.extend(_hardcode_scan_errors(run.id, run.hardcode_scan_result))
        errors.extend(_duplicate_target_set_errors(run.target_set))
        errors.extend(_scored_finalization_errors(run))
        errors.extend(_scoring_summary_errors(run))
        errors.extend(_closed_book_source_ref_errors(run))
        errors.extend(_duplicate_target_result_errors(run.solve_results))
        errors.extend(_target_set_membership_errors(run))
        errors.extend(_scored_target_coverage_errors(run))
        errors.extend(_unresolved("target_id", run.target_set, known_targets))
        for solve_result in run.solve_results:
            solve_session_id = str(solve_result.get("solve_session_id", "")).strip()
            target_id = str(solve_result.get("target_id", "")).strip()
            if solve_session_id not in known_sessions:
                errors.append(f"unresolved solve_session_id: {solve_session_id}")
            if target_id not in known_targets:
                errors.append(f"unresolved target_id: {target_id}")
            errors.extend(_unresolved("evidence_id", solve_result.get("evidence_ids", ()), known_evidence))
            errors.extend(
                _unresolved("policy_decision_id", solve_result.get("policy_decision_ids", ()), known_policies)
            )
            errors.extend(_hardcode_scan_errors(solve_session_id, solve_result.get("hardcode_scan_result", {})))
        return CTFIntegrityResult(status="fail" if errors else "pass", errors=tuple(_deduplicate(errors)))


def _text_set(values: Iterable[str]) -> set[str]:
    return {str(value).strip() for value in values if str(value).strip()}


def _unresolved(label: str, values: Iterable[str], known_values: set[str]) -> list[str]:
    return [f"unresolved {label}: {value}" for value in values if value not in known_values]


def _hardcode_scan_errors(context_id: str, value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return [f"hardcode scan malformed: {context_id}"]
    scan_status = _normalized(value.get("status", ""))
    findings = value.get("findings", ())
    if scan_status in PASS_HARDCODE_SCAN_STATUSES and not findings:
        return []
    if scan_status in SKIPPED_HARDCODE_SCAN_STATUSES:
        return [f"hardcode scan not run: {context_id}"]
    if not isinstance(findings, (list, tuple)):
        return [f"hardcode scan findings malformed: {context_id}"]
    if scan_status not in PASS_HARDCODE_SCAN_STATUSES and not findings:
        return [f"hardcode scan fail without findings: {context_id}"]
    errors: list[str] = []
    for finding in findings:
        rule_id = _finding_rule_id(finding)
        severity = _finding_severity(finding)
        if not severity:
            errors.append(f"hardcode scan finding missing severity: {context_id} {rule_id}")
        elif severity in HARD_FAIL_HARDCODE_SEVERITIES:
            errors.append(f"hardcode scan hard_fail finding: {context_id} {rule_id}")
        elif severity not in REVIEW_HARDCODE_SEVERITIES:
            errors.append(f"hardcode scan unknown severity: {context_id} {rule_id} {severity}")
    return errors


def _scoring_summary_errors(run: BenchmarkRun) -> list[str]:
    if not run.scoring_summary:
        return []
    if not isinstance(run.scoring_summary, Mapping):
        return [f"scoring summary malformed: {run.id}"]
    expected = compute_scoring_summary(run.solve_results)
    errors: list[str] = []
    for key, value in run.scoring_summary.items():
        if not is_scoring_counter(value):
            errors.append(f"scoring summary invalid value: {key}={value}")
    for key in SCORING_KEYS:
        actual = run.scoring_summary.get(key)
        if actual != expected[key]:
            errors.append(f"scoring summary mismatch: {key} expected {expected[key]} got {actual}")
    return errors


def _scored_finalization_errors(run: BenchmarkRun) -> list[str]:
    if str(run.ended_at).strip() and not run.scoring_summary:
        return [f"finalized benchmark missing scoring_summary: {run.id}"]
    if run.scoring_summary and not str(run.ended_at).strip():
        return [f"scored benchmark missing ended_at: {run.id}"]
    return []


def _closed_book_source_ref_errors(run: BenchmarkRun) -> list[str]:
    if not run.scoring_summary or _normalized(run.benchmark_mode) not in CLOSED_BOOK_MODES:
        return []
    errors: list[str] = []
    for solve_result in run.solve_results:
        target_id = str(solve_result.get("target_id", "")).strip()
        source_refs = solve_result.get("source_refs", ())
        if not isinstance(source_refs, (list, tuple)):
            errors.append(f"closed-book solve result source_refs malformed: {target_id}")
            continue
        if _normalized(str(solve_result.get("solve_status", ""))) in {"solved", "complete", "completed"} and not source_refs:
            errors.append(f"closed-book solved result missing source_refs: {target_id}")
        for source_ref in _source_ref_tuple(source_refs):
            if _is_forbidden_active_source_ref(source_ref):
                errors.append(f"closed-book solve result uses forbidden source_ref: {source_ref}")
    return errors


def _duplicate_target_result_errors(solve_results: tuple[dict[str, Any], ...]) -> list[str]:
    seen: set[str] = set()
    duplicates: list[str] = []
    for solve_result in solve_results:
        target_id = str(solve_result.get("target_id", "")).strip()
        if not target_id:
            continue
        if target_id in seen:
            duplicates.append(f"duplicate solve result for target_id: {target_id}")
        seen.add(target_id)
    return duplicates


def _duplicate_target_set_errors(target_set: tuple[str, ...]) -> list[str]:
    seen: set[str] = set()
    duplicates: list[str] = []
    for target_id in target_set:
        if target_id in seen:
            duplicates.append(f"duplicate benchmark target_set entry: {target_id}")
        seen.add(target_id)
    return duplicates


def _target_set_membership_errors(run: BenchmarkRun) -> list[str]:
    allowed_targets = set(run.target_set)
    errors: list[str] = []
    for solve_result in run.solve_results:
        target_id = str(solve_result.get("target_id", "")).strip()
        if target_id and target_id not in allowed_targets:
            errors.append(f"benchmark solve result outside target_set: {target_id}")
    return errors


def _scored_target_coverage_errors(run: BenchmarkRun) -> list[str]:
    if not run.scoring_summary:
        return []
    recorded_targets = {
        str(solve_result.get("target_id", "")).strip()
        for solve_result in run.solve_results
        if str(solve_result.get("target_id", "")).strip()
    }
    return [
        f"missing solve result for target_id: {target_id}"
        for target_id in run.target_set
        if target_id not in recorded_targets
    ]


def _finding_rule_id(finding: Any) -> str:
    if isinstance(finding, Mapping):
        return str(finding.get("rule_id", "unknown")).strip() or "unknown"
    return str(getattr(finding, "rule_id", "unknown")).strip() or "unknown"


def _finding_severity(finding: Any) -> str:
    if isinstance(finding, Mapping):
        return _normalized(finding.get("severity", ""))
    return _normalized(getattr(finding, "severity", ""))


def _source_ref_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(str(item).strip() for item in value if str(item).strip())


def _is_forbidden_active_source_ref(source_ref: str) -> bool:
    normalized = _normalized(source_ref).replace(":", "_").replace("/", "_")
    return any(marker in normalized for marker in FORBIDDEN_ACTIVE_SOURCE_REF_MARKERS)


def _normalized(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _deduplicate(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)
