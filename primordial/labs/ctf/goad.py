from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from primordial.labs.ctf.environment import EnvironmentProof
from primordial.labs.ctf.hidden_material import reject_hidden_flag_material
from primordial.labs.ctf.phases import CTFLabPhase
from primordial.labs.ctf.targets import CTFTarget


GOAD_TARGET_FAMILIES = frozenset({"goad_light", "goad"})
GOAD_EXIT_GATES = (
    "kerberos_and_smb_actions_policy_gated",
    "credential_use_requires_operator_supplied_material",
)
ALLOWED_PROTOCOLS = frozenset({"kerberos", "ldap", "smb", "winrm"})


@dataclass(frozen=True, slots=True)
class GOADPhaseControlResult:
    target_id: str
    status: str
    domain: str
    action_ids: tuple[str, ...]
    credential_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    exit_gates: tuple[str, ...]

    def as_payload(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "status": self.status,
            "domain": self.domain,
            "action_ids": list(self.action_ids),
            "credential_ids": list(self.credential_ids),
            "evidence_refs": list(self.evidence_refs),
            "exit_gates": list(self.exit_gates),
        }


def verify_goad_phase_controls(
    phase: CTFLabPhase,
    target: CTFTarget,
    *,
    environment_proof: EnvironmentProof,
    allowed_actions: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    credential_material: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> GOADPhaseControlResult:
    payload = {
        "phase_id": phase.id,
        "target_id": target.id,
        "environment_proof": environment_proof.as_payload(),
        "allowed_actions": list(allowed_actions) if isinstance(allowed_actions, (list, tuple)) else allowed_actions,
        "credential_material": list(credential_material) if isinstance(credential_material, (list, tuple)) else credential_material,
    }
    reject_hidden_flag_material(payload, path="goad_phase_controls", label="GOADPhaseControlResult")
    _validate_phase_and_target(phase, target, environment_proof)
    credential_ids, credential_refs, credential_evidence_refs = _validate_credential_material(target, credential_material)
    action_ids, action_evidence_refs = _validate_allowed_actions(target, allowed_actions, credential_refs)
    evidence_refs = _unique_refs(environment_proof.evidence_refs + credential_evidence_refs + action_evidence_refs)
    return GOADPhaseControlResult(
        target_id=target.id,
        status="verified",
        domain=str(environment_proof.provisioning.get("domain", "")).strip(),
        action_ids=action_ids,
        credential_ids=credential_ids,
        evidence_refs=evidence_refs,
        exit_gates=GOAD_EXIT_GATES,
    )


def _validate_phase_and_target(phase: CTFLabPhase, target: CTFTarget, proof: EnvironmentProof) -> None:
    if target.target_family not in GOAD_TARGET_FAMILIES:
        raise ValueError("GOAD controls require goad_light or goad target_family")
    if target.target_family not in phase.target_families:
        raise ValueError("GOAD controls target_family must be allowed by phase")
    missing_gates = [gate for gate in GOAD_EXIT_GATES if gate not in phase.exit_gates]
    if "local_ad_lab_environment_verified" not in phase.exit_gates:
        missing_gates.append("local_ad_lab_environment_verified")
    if missing_gates:
        raise ValueError("GOAD controls phase is missing exit gate(s): " + ", ".join(missing_gates))
    if not phase.environment_proof_required:
        raise ValueError("GOAD controls require environment_proof_required phase")
    if proof.target_id != target.id:
        raise ValueError("GOAD controls environment proof target_id must match target")
    if proof.status != "verified" or proof.environment_kind != "local_ad_lab":
        raise ValueError("GOAD controls require verified local AD lab environment proof")
    if "local_ad_lab_environment_verified" not in proof.exit_gates:
        raise ValueError("GOAD controls require local_ad_lab_environment_verified proof")


def _validate_credential_material(
    target: CTFTarget,
    credential_material: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    if not isinstance(credential_material, (list, tuple)) or not credential_material:
        raise ValueError("GOAD controls require credential_material")
    credential_ids: list[str] = []
    credential_refs: list[str] = []
    evidence_refs: list[str] = []
    for index, value in enumerate(credential_material):
        item = _mapping(value, source=f"credential_material[{index}]")
        credential_id = _required_text(item.get("id"), f"credential_material[{index}].id")
        if credential_id in credential_ids:
            raise ValueError(f"GOAD controls duplicate credential id: {credential_id}")
        _validate_target_id(target, item.get("target_id"), source=f"credential_material[{index}].target_id")
        source = _normalized(_required_text(item.get("source"), f"credential_material[{index}].source"))
        if source != "operator_supplied":
            raise ValueError("GOAD controls credential source must be operator_supplied")
        credential_ref = _operator_credential_ref(
            item.get("credential_ref"),
            source=f"credential_material[{index}].credential_ref",
        )
        credential_ids.append(credential_id)
        credential_refs.append(credential_ref)
        evidence_refs.extend(_evidence_refs(item.get("evidence_ids"), source=f"credential_material[{index}].evidence_ids"))
    return tuple(credential_ids), tuple(credential_refs), _unique_refs(tuple(evidence_refs))


def _validate_allowed_actions(
    target: CTFTarget,
    allowed_actions: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    credential_refs: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(allowed_actions, (list, tuple)) or not allowed_actions:
        raise ValueError("GOAD controls require allowed_actions")
    action_ids: list[str] = []
    evidence_refs: list[str] = []
    for index, value in enumerate(allowed_actions):
        item = _mapping(value, source=f"allowed_actions[{index}]")
        action_id = _required_text(item.get("id"), f"allowed_actions[{index}].id")
        if action_id in action_ids:
            raise ValueError(f"GOAD controls duplicate action id: {action_id}")
        _validate_target_id(target, item.get("target_id"), source=f"allowed_actions[{index}].target_id")
        protocol = _normalized(_required_text(item.get("protocol"), f"allowed_actions[{index}].protocol"))
        if protocol not in ALLOWED_PROTOCOLS:
            raise ValueError("GOAD controls protocol must be Kerberos, LDAP, SMB, or WinRM")
        _validate_asset(target, item.get("asset"), source=f"allowed_actions[{index}].asset")
        intent = _normalized(_required_text(item.get("intent"), f"allowed_actions[{index}].intent"))
        if intent != "local_lab_validation":
            raise ValueError("GOAD controls action intent must be local_lab_validation")
        credential_ref = _operator_credential_ref(
            item.get("credential_ref"),
            source=f"allowed_actions[{index}].credential_ref",
        )
        if credential_ref not in credential_refs:
            raise ValueError("GOAD controls action credential_ref must reference operator_supplied material")
        if bool(item.get("external_domain", False)):
            raise ValueError("GOAD controls reject external AD domain actions")
        action_ids.append(action_id)
        evidence_refs.extend(_evidence_refs(item.get("evidence_ids"), source=f"allowed_actions[{index}].evidence_ids"))
    return tuple(action_ids), _unique_refs(tuple(evidence_refs))


def _mapping(value: Mapping[str, Any], *, source: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"GOAD controls {source} must be an object")
    return dict(value)


def _validate_target_id(target: CTFTarget, value: Any, *, source: str) -> None:
    target_id = _required_text(value, source)
    if target_id != target.id:
        raise ValueError(f"GOAD controls {source} must match target")


def _validate_asset(target: CTFTarget, value: Any, *, source: str) -> None:
    asset = _required_text(value, source)
    if asset not in target.scope.assets:
        raise ValueError(f"GOAD controls {source} must stay in lab scope")


def _operator_credential_ref(value: Any, *, source: str) -> str:
    ref = _required_text(value, source)
    if not ref.startswith("operator:credential:"):
        raise ValueError(f"GOAD controls {source} must reference operator-supplied credential material")
    return ref


def _evidence_refs(value: Any, *, source: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError(f"GOAD controls require {source}")
    refs = tuple(_evidence_ref(item, source=f"{source} entry") for item in value)
    if len(set(refs)) != len(refs):
        raise ValueError(f"GOAD controls duplicate {source} entry")
    return refs


def _evidence_ref(value: Any, *, source: str) -> str:
    text = _required_text(value, source)
    if not text.startswith("evidence:"):
        raise ValueError(f"GOAD controls {source} must use evidence:<id>")
    return text


def _unique_refs(refs: tuple[str, ...]) -> tuple[str, ...]:
    unique: list[str] = []
    for ref in refs:
        if ref not in unique:
            unique.append(ref)
    return tuple(unique)


def _required_text(value: Any, source: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"GOAD controls require {source}")
    return text


def _normalized(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")
