from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from primordial.labs.ctf.environment import EnvironmentProof
from primordial.labs.ctf.hidden_material import reject_hidden_flag_material
from primordial.labs.ctf.phases import CTFLabPhase
from primordial.labs.ctf.targets import CTFTarget


CLOUDGOAT_TARGET_FAMILY = "cloudgoat"
CLOUDGOAT_EXIT_GATES = (
    "sandbox_cloud_account_verified",
    "account_boundary_and_region_scope_enforced",
    "teardown_evidence_recorded",
)


@dataclass(frozen=True, slots=True)
class CloudGoatPhaseControlResult:
    target_id: str
    status: str
    account_id: str
    region: str
    resource_ids: tuple[str, ...]
    teardown_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    exit_gates: tuple[str, ...]

    def as_payload(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "status": self.status,
            "account_id": self.account_id,
            "region": self.region,
            "resource_ids": list(self.resource_ids),
            "teardown_ids": list(self.teardown_ids),
            "evidence_refs": list(self.evidence_refs),
            "exit_gates": list(self.exit_gates),
        }


def verify_cloudgoat_phase_controls(
    phase: CTFLabPhase,
    target: CTFTarget,
    *,
    environment_proof: EnvironmentProof,
    account_id: str,
    region: str,
    scoped_resources: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    teardown_actions: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> CloudGoatPhaseControlResult:
    payload = {
        "phase_id": phase.id,
        "target_id": target.id,
        "environment_proof": environment_proof.as_payload(),
        "account_id": account_id,
        "region": region,
        "scoped_resources": list(scoped_resources) if isinstance(scoped_resources, (list, tuple)) else scoped_resources,
        "teardown_actions": list(teardown_actions) if isinstance(teardown_actions, (list, tuple)) else teardown_actions,
    }
    reject_hidden_flag_material(payload, path="cloudgoat_phase_controls", label="CloudGoatPhaseControlResult")
    checked_account_id = _account_id(account_id)
    checked_region = _region(region)
    _validate_phase_and_target(phase, target, environment_proof, account_id=checked_account_id, region=checked_region)
    resource_ids, resource_evidence_refs = _validate_scoped_resources(
        target,
        checked_account_id,
        checked_region,
        scoped_resources,
    )
    teardown_ids, teardown_evidence_refs = _validate_teardown_actions(
        target,
        environment_proof,
        checked_account_id,
        checked_region,
        teardown_actions,
    )
    evidence_refs = _unique_refs(environment_proof.evidence_refs + resource_evidence_refs + teardown_evidence_refs)
    return CloudGoatPhaseControlResult(
        target_id=target.id,
        status="verified",
        account_id=checked_account_id,
        region=checked_region,
        resource_ids=resource_ids,
        teardown_ids=teardown_ids,
        evidence_refs=evidence_refs,
        exit_gates=CLOUDGOAT_EXIT_GATES,
    )


def _validate_phase_and_target(
    phase: CTFLabPhase,
    target: CTFTarget,
    proof: EnvironmentProof,
    *,
    account_id: str,
    region: str,
) -> None:
    if target.target_family != CLOUDGOAT_TARGET_FAMILY:
        raise ValueError("CloudGoat controls require cloudgoat target_family")
    if target.target_family not in phase.target_families:
        raise ValueError("CloudGoat controls target_family must be allowed by phase")
    missing_gates = [gate for gate in CLOUDGOAT_EXIT_GATES if gate not in phase.exit_gates]
    if missing_gates:
        raise ValueError("CloudGoat controls phase is missing exit gate(s): " + ", ".join(missing_gates))
    if not phase.environment_proof_required:
        raise ValueError("CloudGoat controls require environment_proof_required phase")
    if proof.target_id != target.id:
        raise ValueError("CloudGoat controls environment proof target_id must match target")
    if proof.status != "verified" or proof.environment_kind != "sandbox_cloud_account":
        raise ValueError("CloudGoat controls require verified sandbox cloud account proof")
    if "sandbox_cloud_account_verified" not in proof.exit_gates:
        raise ValueError("CloudGoat controls require sandbox_cloud_account_verified proof")
    if str(proof.provisioning.get("account_id", "")).strip() != account_id:
        raise ValueError("CloudGoat controls account_id must match environment proof")
    regions = tuple(str(item) for item in proof.provisioning.get("regions", ()))
    if region not in regions:
        raise ValueError("CloudGoat controls region must match environment proof")


def _validate_scoped_resources(
    target: CTFTarget,
    account_id: str,
    region: str,
    scoped_resources: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(scoped_resources, (list, tuple)) or not scoped_resources:
        raise ValueError("CloudGoat controls require scoped_resources")
    resource_ids: list[str] = []
    evidence_refs: list[str] = []
    for index, value in enumerate(scoped_resources):
        item = _mapping(value, source=f"scoped_resources[{index}]")
        resource_id = _required_text(item.get("id"), f"scoped_resources[{index}].id")
        if resource_id in resource_ids:
            raise ValueError(f"CloudGoat controls duplicate resource id: {resource_id}")
        _validate_target_id(target, item.get("target_id"), source=f"scoped_resources[{index}].target_id")
        _validate_account(account_id, item.get("account_id"), source=f"scoped_resources[{index}].account_id")
        _validate_region(region, item.get("region"), source=f"scoped_resources[{index}].region")
        _validate_asset(target, item.get("asset"), source=f"scoped_resources[{index}].asset")
        _required_text(item.get("resource_type"), f"scoped_resources[{index}].resource_type")
        _text_refs(item.get("source_refs"), source=f"scoped_resources[{index}].source_refs")
        if bool(item.get("public_access", False)) or bool(item.get("cross_account", False)):
            raise ValueError("CloudGoat controls scoped_resources must stay inside account boundary")
        resource_ids.append(resource_id)
        evidence_refs.extend(_evidence_refs(item.get("evidence_ids"), source=f"scoped_resources[{index}].evidence_ids"))
    return tuple(resource_ids), _unique_refs(tuple(evidence_refs))


def _validate_teardown_actions(
    target: CTFTarget,
    proof: EnvironmentProof,
    account_id: str,
    region: str,
    teardown_actions: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(teardown_actions, (list, tuple)) or not teardown_actions:
        raise ValueError("CloudGoat controls require teardown_actions")
    teardown_ids: list[str] = []
    evidence_refs: list[str] = []
    for index, value in enumerate(teardown_actions):
        item = _mapping(value, source=f"teardown_actions[{index}]")
        teardown_id = _required_text(item.get("id"), f"teardown_actions[{index}].id")
        if teardown_id in teardown_ids:
            raise ValueError(f"CloudGoat controls duplicate teardown id: {teardown_id}")
        _validate_target_id(target, item.get("target_id"), source=f"teardown_actions[{index}].target_id")
        _validate_account(account_id, item.get("account_id"), source=f"teardown_actions[{index}].account_id")
        _validate_region(region, item.get("region"), source=f"teardown_actions[{index}].region")
        _required_text(item.get("action"), f"teardown_actions[{index}].action")
        teardown_ref = _evidence_ref(
            item.get("teardown_evidence_ref"),
            source=f"teardown_actions[{index}].teardown_evidence_ref",
        )
        if teardown_ref != proof.reset_evidence_ref:
            raise ValueError("CloudGoat controls teardown_evidence_ref must match environment proof")
        refs = _evidence_refs(item.get("evidence_ids"), source=f"teardown_actions[{index}].evidence_ids")
        if teardown_ref not in refs:
            raise ValueError("CloudGoat controls teardown evidence_ids must include teardown_evidence_ref")
        teardown_ids.append(teardown_id)
        evidence_refs.extend(refs)
    return tuple(teardown_ids), _unique_refs(tuple(evidence_refs))


def _mapping(value: Mapping[str, Any], *, source: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"CloudGoat controls {source} must be an object")
    return dict(value)


def _validate_target_id(target: CTFTarget, value: Any, *, source: str) -> None:
    target_id = _required_text(value, source)
    if target_id != target.id:
        raise ValueError(f"CloudGoat controls {source} must match target")


def _validate_account(expected: str, value: Any, *, source: str) -> None:
    observed = _account_id(value)
    if observed != expected:
        raise ValueError(f"CloudGoat controls {source} must match account")


def _validate_region(expected: str, value: Any, *, source: str) -> None:
    observed = _region(value)
    if observed != expected:
        raise ValueError(f"CloudGoat controls {source} must match region")


def _validate_asset(target: CTFTarget, value: Any, *, source: str) -> None:
    asset = _required_text(value, source)
    if asset not in target.scope.assets:
        raise ValueError(f"CloudGoat controls {source} must stay in lab scope")


def _text_refs(value: Any, *, source: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError(f"CloudGoat controls require {source}")
    return tuple(_required_text(item, f"{source} entry") for item in value)


def _evidence_refs(value: Any, *, source: str) -> tuple[str, ...]:
    refs = tuple(_evidence_ref(item, source=f"{source} entry") for item in _text_refs(value, source=source))
    if len(set(refs)) != len(refs):
        raise ValueError(f"CloudGoat controls duplicate {source} entry")
    return refs


def _evidence_ref(value: Any, *, source: str) -> str:
    text = _required_text(value, source)
    if not text.startswith("evidence:"):
        raise ValueError(f"CloudGoat controls {source} must use evidence:<id>")
    return text


def _unique_refs(refs: tuple[str, ...]) -> tuple[str, ...]:
    unique: list[str] = []
    for ref in refs:
        if ref not in unique:
            unique.append(ref)
    return tuple(unique)


def _account_id(value: Any) -> str:
    account_id = _required_text(value, "account_id")
    if len(account_id) != 12 or not account_id.isdigit():
        raise ValueError("CloudGoat controls require 12-digit account_id")
    return account_id


def _region(value: Any) -> str:
    region = _required_text(value, "region")
    if " " in region or len(region.split("-")) < 3:
        raise ValueError("CloudGoat controls require cloud region")
    return region


def _required_text(value: Any, source: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"CloudGoat controls require {source}")
    return text
