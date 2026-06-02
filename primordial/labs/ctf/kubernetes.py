from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from primordial.labs.ctf.environment import EnvironmentProof
from primordial.labs.ctf.hidden_material import reject_hidden_flag_material
from primordial.labs.ctf.phases import CTFLabPhase
from primordial.labs.ctf.targets import CTFTarget


KUBERNETES_GOAT_TARGET_FAMILY = "kubernetes_goat"
KUBERNETES_GOAT_EXIT_GATES = (
    "local_cluster_environment_verified",
    "namespace_scope_enforced",
    "cluster_mutations_reset_between_runs",
)


@dataclass(frozen=True, slots=True)
class KubernetesGoatPhaseControlResult:
    target_id: str
    status: str
    namespace: str
    resource_ids: tuple[str, ...]
    reset_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    exit_gates: tuple[str, ...]

    def as_payload(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "status": self.status,
            "namespace": self.namespace,
            "resource_ids": list(self.resource_ids),
            "reset_ids": list(self.reset_ids),
            "evidence_refs": list(self.evidence_refs),
            "exit_gates": list(self.exit_gates),
        }


def verify_kubernetes_goat_phase_controls(
    phase: CTFLabPhase,
    target: CTFTarget,
    *,
    environment_proof: EnvironmentProof,
    namespace: str,
    scoped_resources: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    mutation_resets: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> KubernetesGoatPhaseControlResult:
    payload = {
        "phase_id": phase.id,
        "target_id": target.id,
        "environment_proof": environment_proof.as_payload(),
        "namespace": namespace,
        "scoped_resources": list(scoped_resources) if isinstance(scoped_resources, (list, tuple)) else scoped_resources,
        "mutation_resets": list(mutation_resets) if isinstance(mutation_resets, (list, tuple)) else mutation_resets,
    }
    reject_hidden_flag_material(payload, path="kubernetes_goat_phase_controls", label="KubernetesGoatPhaseControlResult")
    checked_namespace = _namespace(namespace)
    _validate_phase_and_target(phase, target, environment_proof, namespace=checked_namespace)
    resource_ids, resource_evidence_refs = _validate_scoped_resources(target, checked_namespace, scoped_resources)
    reset_ids, reset_evidence_refs = _validate_mutation_resets(target, environment_proof, checked_namespace, mutation_resets)
    evidence_refs = _unique_refs(environment_proof.evidence_refs + resource_evidence_refs + reset_evidence_refs)
    return KubernetesGoatPhaseControlResult(
        target_id=target.id,
        status="verified",
        namespace=checked_namespace,
        resource_ids=resource_ids,
        reset_ids=reset_ids,
        evidence_refs=evidence_refs,
        exit_gates=KUBERNETES_GOAT_EXIT_GATES,
    )


def _validate_phase_and_target(
    phase: CTFLabPhase,
    target: CTFTarget,
    proof: EnvironmentProof,
    *,
    namespace: str,
) -> None:
    if target.target_family != KUBERNETES_GOAT_TARGET_FAMILY:
        raise ValueError("Kubernetes Goat controls require kubernetes_goat target_family")
    if target.target_family not in phase.target_families:
        raise ValueError("Kubernetes Goat controls target_family must be allowed by phase")
    missing_gates = [gate for gate in KUBERNETES_GOAT_EXIT_GATES if gate not in phase.exit_gates]
    if missing_gates:
        raise ValueError("Kubernetes Goat controls phase is missing exit gate(s): " + ", ".join(missing_gates))
    if not phase.environment_proof_required:
        raise ValueError("Kubernetes Goat controls require environment_proof_required phase")
    if proof.target_id != target.id:
        raise ValueError("Kubernetes Goat controls environment proof target_id must match target")
    if proof.status != "verified" or proof.environment_kind != "local_cluster":
        raise ValueError("Kubernetes Goat controls require verified local cluster environment proof")
    if "local_cluster_environment_verified" not in proof.exit_gates:
        raise ValueError("Kubernetes Goat controls require local_cluster_environment_verified proof")
    if str(proof.provisioning.get("namespace", "")).strip() != namespace:
        raise ValueError("Kubernetes Goat controls namespace must match environment proof")


def _validate_scoped_resources(
    target: CTFTarget,
    namespace: str,
    scoped_resources: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(scoped_resources, (list, tuple)) or not scoped_resources:
        raise ValueError("Kubernetes Goat controls require scoped_resources")
    resource_ids: list[str] = []
    evidence_refs: list[str] = []
    for index, value in enumerate(scoped_resources):
        item = _mapping(value, source=f"scoped_resources[{index}]")
        resource_id = _required_text(item.get("id"), f"scoped_resources[{index}].id")
        if resource_id in resource_ids:
            raise ValueError(f"Kubernetes Goat controls duplicate resource id: {resource_id}")
        _validate_target_id(target, item.get("target_id"), source=f"scoped_resources[{index}].target_id")
        _validate_namespace(namespace, item.get("namespace"), source=f"scoped_resources[{index}].namespace")
        _required_text(item.get("kind"), f"scoped_resources[{index}].kind")
        _required_text(item.get("name"), f"scoped_resources[{index}].name")
        _validate_asset(target, item.get("asset"), source=f"scoped_resources[{index}].asset")
        _text_refs(item.get("source_refs"), source=f"scoped_resources[{index}].source_refs")
        resource_ids.append(resource_id)
        evidence_refs.extend(_evidence_refs(item.get("evidence_ids"), source=f"scoped_resources[{index}].evidence_ids"))
    return tuple(resource_ids), _unique_refs(tuple(evidence_refs))


def _validate_mutation_resets(
    target: CTFTarget,
    proof: EnvironmentProof,
    namespace: str,
    mutation_resets: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(mutation_resets, (list, tuple)) or not mutation_resets:
        raise ValueError("Kubernetes Goat controls require mutation_resets")
    reset_ids: list[str] = []
    evidence_refs: list[str] = []
    for index, value in enumerate(mutation_resets):
        item = _mapping(value, source=f"mutation_resets[{index}]")
        reset_id = _required_text(item.get("id"), f"mutation_resets[{index}].id")
        if reset_id in reset_ids:
            raise ValueError(f"Kubernetes Goat controls duplicate reset id: {reset_id}")
        _validate_target_id(target, item.get("target_id"), source=f"mutation_resets[{index}].target_id")
        _validate_namespace(namespace, item.get("namespace"), source=f"mutation_resets[{index}].namespace")
        _required_text(item.get("action"), f"mutation_resets[{index}].action")
        if bool(item.get("cluster_scope", False)):
            raise ValueError("Kubernetes Goat controls mutation reset must stay inside namespace")
        reset_ref = _evidence_ref(item.get("reset_evidence_ref"), source=f"mutation_resets[{index}].reset_evidence_ref")
        if reset_ref != proof.reset_evidence_ref:
            raise ValueError("Kubernetes Goat controls reset_evidence_ref must match environment proof")
        reset_ids.append(reset_id)
        evidence_refs.extend(_evidence_refs(item.get("evidence_ids"), source=f"mutation_resets[{index}].evidence_ids"))
    return tuple(reset_ids), _unique_refs(tuple(evidence_refs))


def _mapping(value: Mapping[str, Any], *, source: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"Kubernetes Goat controls {source} must be an object")
    return dict(value)


def _validate_target_id(target: CTFTarget, value: Any, *, source: str) -> None:
    target_id = _required_text(value, source)
    if target_id != target.id:
        raise ValueError(f"Kubernetes Goat controls {source} must match target")


def _validate_namespace(expected: str, value: Any, *, source: str) -> None:
    observed = _namespace(_required_text(value, source))
    if observed != expected:
        raise ValueError(f"Kubernetes Goat controls {source} must match namespace")


def _validate_asset(target: CTFTarget, value: Any, *, source: str) -> None:
    asset = _required_text(value, source)
    if asset not in target.scope.assets:
        raise ValueError(f"Kubernetes Goat controls {source} must stay in lab scope")


def _text_refs(value: Any, *, source: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError(f"Kubernetes Goat controls require {source}")
    return tuple(_required_text(item, f"{source} entry") for item in value)


def _evidence_refs(value: Any, *, source: str) -> tuple[str, ...]:
    refs = tuple(_evidence_ref(item, source=f"{source} entry") for item in _text_refs(value, source=source))
    if len(set(refs)) != len(refs):
        raise ValueError(f"Kubernetes Goat controls duplicate {source} entry")
    return refs


def _evidence_ref(value: Any, *, source: str) -> str:
    text = _required_text(value, source)
    if not text.startswith("evidence:"):
        raise ValueError(f"Kubernetes Goat controls {source} must use evidence:<id>")
    return text


def _unique_refs(refs: tuple[str, ...]) -> tuple[str, ...]:
    unique: list[str] = []
    for ref in refs:
        if ref not in unique:
            unique.append(ref)
    return tuple(unique)


def _namespace(value: str) -> str:
    namespace = str(value or "").strip()
    if not namespace:
        raise ValueError("Kubernetes Goat controls require namespace")
    if namespace in {"*", "all", "default", "kube-node-lease", "kube-public", "kube-system"}:
        raise ValueError("Kubernetes Goat controls namespace must be dedicated to the local lab")
    return namespace


def _required_text(value: Any, source: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"Kubernetes Goat controls require {source}")
    return text
