from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from primordial.labs.ctf.environment import EnvironmentProof
from primordial.labs.ctf.hidden_material import reject_hidden_flag_material
from primordial.labs.ctf.phases import CTFLabPhase
from primordial.labs.ctf.targets import CTFTarget


CICD_GOAT_TARGET_FAMILY = "ci_cd_goat"
CICD_GOAT_EXIT_GATES = (
    "ci_cd_attack_paths_bound_to_lab_scope",
    "no_external_pipeline_mutation_without_verified_lab",
)
MUTATING_PIPELINE_ACTIONS = frozenset(
    {
        "commit",
        "create_branch",
        "push",
        "run_job",
        "trigger_pipeline",
        "update_pipeline",
        "write_repository",
    }
)


@dataclass(frozen=True, slots=True)
class CICDGoatPhaseControlResult:
    target_id: str
    status: str
    attack_path_ids: tuple[str, ...]
    pipeline_action_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    exit_gates: tuple[str, ...]

    def as_payload(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "status": self.status,
            "attack_path_ids": list(self.attack_path_ids),
            "pipeline_action_ids": list(self.pipeline_action_ids),
            "evidence_refs": list(self.evidence_refs),
            "exit_gates": list(self.exit_gates),
        }


def verify_cicd_goat_phase_controls(
    phase: CTFLabPhase,
    target: CTFTarget,
    *,
    environment_proof: EnvironmentProof,
    attack_paths: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    pipeline_actions: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> CICDGoatPhaseControlResult:
    payload = {
        "phase_id": phase.id,
        "target_id": target.id,
        "environment_proof": environment_proof.as_payload(),
        "attack_paths": list(attack_paths) if isinstance(attack_paths, (list, tuple)) else attack_paths,
        "pipeline_actions": list(pipeline_actions) if isinstance(pipeline_actions, (list, tuple)) else pipeline_actions,
    }
    reject_hidden_flag_material(payload, path="cicd_goat_phase_controls", label="CICDGoatPhaseControlResult")
    _validate_phase_and_target(phase, target, environment_proof)
    attack_path_ids, attack_evidence_refs = _validate_attack_paths(target, attack_paths)
    action_ids, action_evidence_refs = _validate_pipeline_actions(target, environment_proof, pipeline_actions)
    evidence_refs = _unique_refs(environment_proof.evidence_refs + attack_evidence_refs + action_evidence_refs)
    return CICDGoatPhaseControlResult(
        target_id=target.id,
        status="verified",
        attack_path_ids=attack_path_ids,
        pipeline_action_ids=action_ids,
        evidence_refs=evidence_refs,
        exit_gates=CICD_GOAT_EXIT_GATES,
    )


def _validate_phase_and_target(phase: CTFLabPhase, target: CTFTarget, proof: EnvironmentProof) -> None:
    if target.target_family != CICD_GOAT_TARGET_FAMILY:
        raise ValueError("CI/CD Goat controls require ci_cd_goat target_family")
    if target.target_family not in phase.target_families:
        raise ValueError("CI/CD Goat controls target_family must be allowed by phase")
    missing_gates = [gate for gate in CICD_GOAT_EXIT_GATES if gate not in phase.exit_gates]
    if "local_container_environment_verified" not in phase.exit_gates:
        missing_gates.append("local_container_environment_verified")
    if missing_gates:
        raise ValueError("CI/CD Goat controls phase is missing exit gate(s): " + ", ".join(missing_gates))
    if not phase.environment_proof_required:
        raise ValueError("CI/CD Goat controls require environment_proof_required phase")
    if proof.target_id != target.id:
        raise ValueError("CI/CD Goat controls environment proof target_id must match target")
    if proof.status != "verified" or "local_container_environment_verified" not in proof.exit_gates:
        raise ValueError("CI/CD Goat controls require verified local container environment proof")


def _validate_attack_paths(
    target: CTFTarget,
    attack_paths: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(attack_paths, (list, tuple)) or not attack_paths:
        raise ValueError("CI/CD Goat controls require attack_paths")
    path_ids: list[str] = []
    evidence_refs: list[str] = []
    for index, value in enumerate(attack_paths):
        item = _mapping(value, source=f"attack_paths[{index}]")
        path_id = _required_text(item.get("id"), f"attack_paths[{index}].id")
        if path_id in path_ids:
            raise ValueError(f"CI/CD Goat controls duplicate attack path id: {path_id}")
        _validate_target_id(target, item.get("target_id"), source=f"attack_paths[{index}].target_id")
        _validate_asset(target, item.get("asset"), source=f"attack_paths[{index}].asset")
        _required_text(item.get("ci_system"), f"attack_paths[{index}].ci_system")
        _text_refs(item.get("source_refs"), source=f"attack_paths[{index}].source_refs")
        path_ids.append(path_id)
        evidence_refs.extend(_evidence_refs(item.get("evidence_ids"), source=f"attack_paths[{index}].evidence_ids"))
    return tuple(path_ids), _unique_refs(tuple(evidence_refs))


def _validate_pipeline_actions(
    target: CTFTarget,
    proof: EnvironmentProof,
    pipeline_actions: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(pipeline_actions, (list, tuple)) or not pipeline_actions:
        raise ValueError("CI/CD Goat controls require pipeline_actions")
    action_ids: list[str] = []
    evidence_refs: list[str] = []
    for index, value in enumerate(pipeline_actions):
        item = _mapping(value, source=f"pipeline_actions[{index}]")
        action_id = _required_text(item.get("id"), f"pipeline_actions[{index}].id")
        if action_id in action_ids:
            raise ValueError(f"CI/CD Goat controls duplicate pipeline action id: {action_id}")
        action = _normalized(_required_text(item.get("action"), f"pipeline_actions[{index}].action"))
        _validate_target_id(target, item.get("target_id"), source=f"pipeline_actions[{index}].target_id")
        _validate_asset(target, item.get("asset"), source=f"pipeline_actions[{index}].asset")
        _validate_local_pipeline_scope(item.get("scope"), source=f"pipeline_actions[{index}].scope")
        environment_ref = _required_text(item.get("environment_ref"), f"pipeline_actions[{index}].environment_ref")
        if action in MUTATING_PIPELINE_ACTIONS and environment_ref not in proof.evidence_refs:
            raise ValueError("CI/CD Goat controls mutating pipeline action requires verified environment_ref")
        if bool(item.get("external_mutation", False)):
            raise ValueError("CI/CD Goat controls reject external pipeline mutation")
        action_ids.append(action_id)
        evidence_refs.extend(_evidence_refs(item.get("evidence_ids"), source=f"pipeline_actions[{index}].evidence_ids"))
    return tuple(action_ids), _unique_refs(tuple(evidence_refs))


def _mapping(value: Mapping[str, Any], *, source: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"CI/CD Goat controls {source} must be an object")
    return dict(value)


def _validate_target_id(target: CTFTarget, value: Any, *, source: str) -> None:
    target_id = _required_text(value, source)
    if target_id != target.id:
        raise ValueError(f"CI/CD Goat controls {source} must match target")


def _validate_asset(target: CTFTarget, value: Any, *, source: str) -> None:
    asset = _required_text(value, source)
    if asset not in target.scope.assets:
        raise ValueError(f"CI/CD Goat controls {source} must stay in lab scope")


def _validate_local_pipeline_scope(value: Any, *, source: str) -> None:
    scope = _normalized(_required_text(value, source))
    if scope != "local_lab":
        raise ValueError(f"CI/CD Goat controls {source} must be local_lab")


def _text_refs(value: Any, *, source: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError(f"CI/CD Goat controls require {source}")
    return tuple(_required_text(item, f"{source} entry") for item in value)


def _evidence_refs(value: Any, *, source: str) -> tuple[str, ...]:
    refs = _text_refs(value, source=source)
    invalid = [ref for ref in refs if not ref.startswith("evidence:")]
    if invalid:
        raise ValueError(f"CI/CD Goat controls {source} entries must use evidence:<id>")
    if len(set(refs)) != len(refs):
        raise ValueError(f"CI/CD Goat controls duplicate {source} entry")
    return refs


def _unique_refs(refs: tuple[str, ...]) -> tuple[str, ...]:
    unique: list[str] = []
    for ref in refs:
        if ref not in unique:
            unique.append(ref)
    return tuple(unique)


def _required_text(value: Any, source: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"CI/CD Goat controls require {source}")
    return text


def _normalized(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")
