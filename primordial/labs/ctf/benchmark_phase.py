from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from primordial.labs.ctf.environment import EnvironmentProof
from primordial.labs.ctf.hidden_material import reject_hidden_flag_material
from primordial.labs.ctf.phases import CTFLabPhase
from primordial.labs.ctf.targets import CTFTarget


BENCHMARK_TARGET_FAMILIES = frozenset({"dreadgoad", "ctf_dojo", "nyu_ctf_bench"})
BENCHMARK_EXIT_GATES = (
    "benchmark_environment_verified",
    "target_rotation_and_reset_verified",
    "aggregate_scoring_uses_evidence_backed_results",
)


@dataclass(frozen=True, slots=True)
class BenchmarkPhaseControlResult:
    target_id: str
    status: str
    rotation_ids: tuple[str, ...]
    scoring_result_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    exit_gates: tuple[str, ...]

    def as_payload(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "status": self.status,
            "rotation_ids": list(self.rotation_ids),
            "scoring_result_ids": list(self.scoring_result_ids),
            "evidence_refs": list(self.evidence_refs),
            "exit_gates": list(self.exit_gates),
        }


def verify_benchmark_phase_controls(
    phase: CTFLabPhase,
    target: CTFTarget,
    *,
    environment_proof: EnvironmentProof,
    target_rotation: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    scoring_results: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> BenchmarkPhaseControlResult:
    payload = {
        "phase_id": phase.id,
        "target_id": target.id,
        "environment_proof": environment_proof.as_payload(),
        "target_rotation": list(target_rotation) if isinstance(target_rotation, (list, tuple)) else target_rotation,
        "scoring_results": list(scoring_results) if isinstance(scoring_results, (list, tuple)) else scoring_results,
    }
    reject_hidden_flag_material(payload, path="benchmark_phase_controls", label="BenchmarkPhaseControlResult")
    _validate_phase_and_target(phase, target, environment_proof)
    rotation_ids, reset_evidence_refs = _validate_target_rotation(target, environment_proof, target_rotation)
    scoring_ids, scoring_evidence_refs = _validate_scoring_results(rotation_ids, scoring_results)
    evidence_refs = _unique_refs(environment_proof.evidence_refs + reset_evidence_refs + scoring_evidence_refs)
    return BenchmarkPhaseControlResult(
        target_id=target.id,
        status="verified",
        rotation_ids=rotation_ids,
        scoring_result_ids=scoring_ids,
        evidence_refs=evidence_refs,
        exit_gates=BENCHMARK_EXIT_GATES,
    )


def _validate_phase_and_target(phase: CTFLabPhase, target: CTFTarget, proof: EnvironmentProof) -> None:
    if target.target_family not in BENCHMARK_TARGET_FAMILIES:
        raise ValueError("Benchmark controls require DreadGOAD, CTF-Dojo, or NYU CTF Bench target_family")
    if target.target_family not in phase.target_families:
        raise ValueError("Benchmark controls target_family must be allowed by phase")
    missing_gates = [gate for gate in BENCHMARK_EXIT_GATES if gate not in phase.exit_gates]
    if missing_gates:
        raise ValueError("Benchmark controls phase is missing exit gate(s): " + ", ".join(missing_gates))
    if not phase.environment_proof_required:
        raise ValueError("Benchmark controls require environment_proof_required phase")
    if proof.target_id != target.id:
        raise ValueError("Benchmark controls environment proof target_id must match target")
    if proof.status != "verified" or proof.environment_kind != "benchmark_environment":
        raise ValueError("Benchmark controls require verified benchmark environment proof")
    if "benchmark_environment_verified" not in proof.exit_gates:
        raise ValueError("Benchmark controls require benchmark_environment_verified proof")


def _validate_target_rotation(
    target: CTFTarget,
    proof: EnvironmentProof,
    target_rotation: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(target_rotation, (list, tuple)) or len(target_rotation) < 2:
        raise ValueError("Benchmark controls require target_rotation with at least two targets")
    expected_rotation = tuple(str(item) for item in proof.provisioning.get("target_rotation", ()))
    rotation_ids: list[str] = []
    evidence_refs: list[str] = []
    for index, value in enumerate(target_rotation):
        item = _mapping(value, source=f"target_rotation[{index}]")
        rotation_id = _required_text(item.get("id"), f"target_rotation[{index}].id")
        if rotation_id in rotation_ids:
            raise ValueError(f"Benchmark controls duplicate rotation id: {rotation_id}")
        if rotation_id not in expected_rotation:
            raise ValueError("Benchmark controls target_rotation must match environment proof")
        _validate_target_id(target, item.get("target_id"), source=f"target_rotation[{index}].target_id")
        _validate_asset(target, item.get("asset"), source=f"target_rotation[{index}].asset")
        reset_ref = _evidence_ref(item.get("reset_evidence_ref"), source=f"target_rotation[{index}].reset_evidence_ref")
        if reset_ref not in proof.evidence_refs:
            raise ValueError("Benchmark controls reset_evidence_ref must be verified")
        rotation_ids.append(rotation_id)
        evidence_refs.extend(_evidence_refs(item.get("evidence_ids"), source=f"target_rotation[{index}].evidence_ids"))
    if tuple(rotation_ids) != expected_rotation:
        raise ValueError("Benchmark controls target_rotation order must match environment proof")
    return tuple(rotation_ids), _unique_refs(tuple(evidence_refs))


def _validate_scoring_results(
    rotation_ids: tuple[str, ...],
    scoring_results: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(scoring_results, (list, tuple)) or not scoring_results:
        raise ValueError("Benchmark controls require scoring_results")
    scoring_ids: list[str] = []
    scored_targets: list[str] = []
    evidence_refs: list[str] = []
    for index, value in enumerate(scoring_results):
        item = _mapping(value, source=f"scoring_results[{index}]")
        scoring_id = _required_text(item.get("id"), f"scoring_results[{index}].id")
        if scoring_id in scoring_ids:
            raise ValueError(f"Benchmark controls duplicate scoring result id: {scoring_id}")
        target_ref = _required_text(item.get("target_ref"), f"scoring_results[{index}].target_ref")
        if target_ref not in rotation_ids:
            raise ValueError("Benchmark controls scoring target_ref must be in target_rotation")
        _score(item.get("score"), source=f"scoring_results[{index}].score")
        scoring_ids.append(scoring_id)
        scored_targets.append(target_ref)
        evidence_refs.extend(_evidence_refs(item.get("evidence_ids"), source=f"scoring_results[{index}].evidence_ids"))
    missing_scores = [target_id for target_id in rotation_ids if target_id not in scored_targets]
    if missing_scores:
        raise ValueError("Benchmark controls require scoring evidence for every rotated target")
    return tuple(scoring_ids), _unique_refs(tuple(evidence_refs))


def _mapping(value: Mapping[str, Any], *, source: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"Benchmark controls {source} must be an object")
    return dict(value)


def _validate_target_id(target: CTFTarget, value: Any, *, source: str) -> None:
    target_id = _required_text(value, source)
    if target_id != target.id:
        raise ValueError(f"Benchmark controls {source} must match target")


def _validate_asset(target: CTFTarget, value: Any, *, source: str) -> None:
    asset = _required_text(value, source)
    if asset not in target.scope.assets:
        raise ValueError(f"Benchmark controls {source} must stay in lab scope")


def _evidence_refs(value: Any, *, source: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError(f"Benchmark controls require {source} evidence")
    refs = tuple(_evidence_ref(item, source=f"{source} entry") for item in value)
    if len(set(refs)) != len(refs):
        raise ValueError(f"Benchmark controls duplicate {source} entry")
    return refs


def _evidence_ref(value: Any, *, source: str) -> str:
    text = _required_text(value, source)
    if not text.startswith("evidence:"):
        raise ValueError(f"Benchmark controls {source} must use evidence:<id>")
    return text


def _score(value: Any, *, source: str) -> float:
    if not isinstance(value, int | float):
        raise ValueError(f"Benchmark controls {source} must be numeric")
    score = float(value)
    if score < 0:
        raise ValueError(f"Benchmark controls {source} must be non-negative")
    return score


def _unique_refs(refs: tuple[str, ...]) -> tuple[str, ...]:
    unique: list[str] = []
    for ref in refs:
        if ref not in unique:
            unique.append(ref)
    return tuple(unique)


def _required_text(value: Any, source: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"Benchmark controls require {source}")
    return text
