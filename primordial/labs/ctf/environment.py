from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from primordial.labs.ctf.applicability import ExploitApplicabilityResult, validate_vulhub_exploit_applicability
from primordial.labs.ctf.environment_helpers import (
    BENCHMARK_MODES,
    BENCHMARK_EXIT_GATES,
    LOCAL_AD_LAB_MODES,
    LOCAL_AD_LAB_EXIT_GATES,
    LOCAL_CLUSTER_MODES,
    LOCAL_CLUSTER_EXIT_GATES,
    LOCAL_CONTAINER_MODES,
    LOCAL_CONTAINER_EXIT_GATES,
    PHASE_LOCAL_LAB_EXIT_GATES,
    SANDBOX_CLOUD_MODES,
    SANDBOX_CLOUD_EXIT_GATES,
    account_id as _account_id,
    domain as _domain,
    evidence_ref as _evidence_ref,
    evidence_ref_tuple as _evidence_ref_tuple,
    observed_assets as _observed_assets,
    observed_vulhub_product_version as _observed_vulhub_product_version,
    observation_evidence_ref as _observation_evidence_ref,
    plain_mapping as _plain_mapping,
    probe_http_asset as _probe_http_asset,
    profile as _profile,
    provisioning_payload as _provisioning_payload,
    regions as _regions,
    rotation as _rotation,
    validate_benchmark_target as _validate_benchmark_target,
    validate_local_ad_lab_target as _validate_local_ad_lab_target,
    validate_local_cluster_target as _validate_local_cluster_target,
    validate_local_container_target as _validate_local_container_target,
    validate_phase_local_lab_target as _validate_phase_local_lab_target,
    validate_sandbox_cloud_target as _validate_sandbox_cloud_target,
    namespace as _namespace,
)
from primordial.labs.ctf.hidden_material import reject_hidden_flag_material
from primordial.labs.ctf.phases import CTFLabPhase
from primordial.labs.ctf.targets import CTFTarget


@dataclass(frozen=True, slots=True)
class EnvironmentProof:
    target_id: str
    status: str
    profile: str
    environment_kind: str
    observed_assets: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    reset_evidence_ref: str
    exit_gates: tuple[str, ...]
    provisioning: Mapping[str, Any]
    observations: Mapping[str, Any]

    def as_payload(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "status": self.status,
            "profile": self.profile,
            "environment_kind": self.environment_kind,
            "observed_assets": list(self.observed_assets),
            "evidence_refs": list(self.evidence_refs),
            "reset_evidence_ref": self.reset_evidence_ref,
            "exit_gates": list(self.exit_gates),
            "provisioning": _plain_mapping(self.provisioning),
            "observations": _plain_mapping(self.observations),
        }


@dataclass(frozen=True, slots=True)
class VulhubEnvironmentProof:
    target_id: str
    observed_product: str
    observed_version: str
    evidence_refs: tuple[str, ...]
    exit_gates: tuple[str, ...]
    environment_proof: EnvironmentProof
    applicability: ExploitApplicabilityResult

    def as_payload(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "observed_product": self.observed_product,
            "observed_version": self.observed_version,
            "evidence_refs": list(self.evidence_refs),
            "exit_gates": list(self.exit_gates),
            "environment_proof": self.environment_proof.as_payload(),
            "applicability": self.applicability.as_payload(),
        }


@dataclass(frozen=True, slots=True)
class PhaseEnvironmentProof:
    phase_number: int
    phase_id: str
    target_id: str
    target_family: str
    status: str
    evidence_refs: tuple[str, ...]
    reset_evidence_ref: str
    exit_gates: tuple[str, ...]
    environment_proof: EnvironmentProof

    def as_payload(self) -> dict[str, Any]:
        return {
            "phase_number": self.phase_number,
            "phase_id": self.phase_id,
            "target_id": self.target_id,
            "target_family": self.target_family,
            "status": self.status,
            "evidence_refs": list(self.evidence_refs),
            "reset_evidence_ref": self.reset_evidence_ref,
            "exit_gates": list(self.exit_gates),
            "environment_proof": self.environment_proof.as_payload(),
        }


def verify_local_container_environment(
    target: CTFTarget,
    *,
    observed_assets: list[str] | tuple[str, ...],
    evidence_refs: list[str] | tuple[str, ...],
    reset_evidence_ref: str,
    profile: str,
    observations: Mapping[str, Any] | None = None,
) -> EnvironmentProof:
    payload = {
        "target_id": target.id,
        "observed_assets": observed_assets,
        "evidence_refs": evidence_refs,
        "reset_evidence_ref": reset_evidence_ref,
        "profile": profile,
        "observations": dict(observations or {}),
    }
    reject_hidden_flag_material(payload, path="ctf_environment_proof", label="EnvironmentProof")
    _validate_local_container_target(target)
    checked_profile = _profile(target, profile)
    checked_assets = _observed_assets(target, observed_assets)
    checked_refs = _evidence_ref_tuple(evidence_refs)
    checked_reset_ref = _evidence_ref(reset_evidence_ref, "reset_evidence_ref")
    if checked_reset_ref not in checked_refs:
        raise ValueError("EnvironmentProof reset_evidence_ref must be included in evidence_refs")
    return EnvironmentProof(
        target_id=target.id,
        status="verified",
        profile=checked_profile,
        environment_kind="local_container",
        observed_assets=checked_assets,
        evidence_refs=checked_refs,
        reset_evidence_ref=checked_reset_ref,
        exit_gates=LOCAL_CONTAINER_EXIT_GATES,
        provisioning=_provisioning_payload(target),
        observations=dict(observations or {}),
    )


def verify_local_cluster_environment(
    target: CTFTarget,
    *,
    namespace: str,
    observed_assets: list[str] | tuple[str, ...],
    evidence_refs: list[str] | tuple[str, ...],
    reset_evidence_ref: str,
    profile: str,
    observations: Mapping[str, Any] | None = None,
) -> EnvironmentProof:
    payload = {
        "target_id": target.id,
        "namespace": namespace,
        "observed_assets": observed_assets,
        "evidence_refs": evidence_refs,
        "reset_evidence_ref": reset_evidence_ref,
        "profile": profile,
        "observations": dict(observations or {}),
    }
    reject_hidden_flag_material(payload, path="ctf_cluster_environment_proof", label="EnvironmentProof")
    _validate_local_cluster_target(target)
    checked_namespace = _namespace(namespace)
    checked_profile = _profile(target, profile)
    checked_assets = _observed_assets(target, observed_assets)
    checked_refs = _evidence_ref_tuple(evidence_refs)
    checked_reset_ref = _evidence_ref(reset_evidence_ref, "reset_evidence_ref")
    if checked_reset_ref not in checked_refs:
        raise ValueError("EnvironmentProof reset_evidence_ref must be included in evidence_refs")
    provisioning = _provisioning_payload(target)
    provisioning["namespace"] = checked_namespace
    return EnvironmentProof(
        target_id=target.id,
        status="verified",
        profile=checked_profile,
        environment_kind="local_cluster",
        observed_assets=checked_assets,
        evidence_refs=checked_refs,
        reset_evidence_ref=checked_reset_ref,
        exit_gates=LOCAL_CLUSTER_EXIT_GATES,
        provisioning=provisioning,
        observations=dict(observations or {}),
    )


def verify_local_ad_lab_environment(
    target: CTFTarget,
    *,
    domain: str,
    observed_assets: list[str] | tuple[str, ...],
    evidence_refs: list[str] | tuple[str, ...],
    reset_evidence_ref: str,
    profile: str,
    observations: Mapping[str, Any] | None = None,
) -> EnvironmentProof:
    payload = {
        "target_id": target.id,
        "domain": domain,
        "observed_assets": observed_assets,
        "evidence_refs": evidence_refs,
        "reset_evidence_ref": reset_evidence_ref,
        "profile": profile,
        "observations": dict(observations or {}),
    }
    reject_hidden_flag_material(payload, path="ctf_ad_lab_environment_proof", label="EnvironmentProof")
    _validate_local_ad_lab_target(target)
    checked_domain = _domain(domain)
    expected_domain = _domain(target.scope.network or target.reset.network)
    if checked_domain != expected_domain:
        raise ValueError("EnvironmentProof local AD domain must match target domain")
    checked_profile = _profile(target, profile)
    checked_assets = _observed_assets(target, observed_assets)
    checked_refs = _evidence_ref_tuple(evidence_refs)
    checked_reset_ref = _evidence_ref(reset_evidence_ref, "reset_evidence_ref")
    if checked_reset_ref not in checked_refs:
        raise ValueError("EnvironmentProof reset_evidence_ref must be included in evidence_refs")
    provisioning = _provisioning_payload(target)
    provisioning["domain"] = checked_domain
    return EnvironmentProof(
        target_id=target.id,
        status="verified",
        profile=checked_profile,
        environment_kind="local_ad_lab",
        observed_assets=checked_assets,
        evidence_refs=checked_refs,
        reset_evidence_ref=checked_reset_ref,
        exit_gates=LOCAL_AD_LAB_EXIT_GATES,
        provisioning=provisioning,
        observations=dict(observations or {}),
    )


def verify_sandbox_cloud_environment(
    target: CTFTarget,
    *,
    account_id: str,
    regions: list[str] | tuple[str, ...],
    observed_assets: list[str] | tuple[str, ...],
    evidence_refs: list[str] | tuple[str, ...],
    reset_evidence_ref: str,
    profile: str,
    observations: Mapping[str, Any] | None = None,
) -> EnvironmentProof:
    payload = {
        "target_id": target.id,
        "account_id": account_id,
        "regions": regions,
        "observed_assets": observed_assets,
        "evidence_refs": evidence_refs,
        "reset_evidence_ref": reset_evidence_ref,
        "profile": profile,
        "observations": dict(observations or {}),
    }
    reject_hidden_flag_material(payload, path="ctf_sandbox_cloud_environment_proof", label="EnvironmentProof")
    _validate_sandbox_cloud_target(target)
    checked_account_id = _account_id(account_id)
    checked_regions = _regions(regions)
    checked_profile = _profile(target, profile)
    checked_assets = _observed_assets(target, observed_assets)
    checked_refs = _evidence_ref_tuple(evidence_refs)
    checked_reset_ref = _evidence_ref(reset_evidence_ref, "reset_evidence_ref")
    if checked_reset_ref not in checked_refs:
        raise ValueError("EnvironmentProof reset_evidence_ref must be included in evidence_refs")
    provisioning = _provisioning_payload(target)
    provisioning["account_id"] = checked_account_id
    provisioning["regions"] = list(checked_regions)
    return EnvironmentProof(
        target_id=target.id,
        status="verified",
        profile=checked_profile,
        environment_kind="sandbox_cloud_account",
        observed_assets=checked_assets,
        evidence_refs=checked_refs,
        reset_evidence_ref=checked_reset_ref,
        exit_gates=SANDBOX_CLOUD_EXIT_GATES,
        provisioning=provisioning,
        observations=dict(observations or {}),
    )


def verify_benchmark_environment(
    target: CTFTarget,
    *,
    observed_assets: list[str] | tuple[str, ...],
    evidence_refs: list[str] | tuple[str, ...],
    reset_evidence_ref: str,
    profile: str,
    target_rotation: list[str] | tuple[str, ...],
    observations: Mapping[str, Any] | None = None,
) -> EnvironmentProof:
    payload = {
        "target_id": target.id,
        "observed_assets": observed_assets,
        "evidence_refs": evidence_refs,
        "reset_evidence_ref": reset_evidence_ref,
        "profile": profile,
        "target_rotation": target_rotation,
        "observations": dict(observations or {}),
    }
    reject_hidden_flag_material(payload, path="ctf_benchmark_environment_proof", label="EnvironmentProof")
    _validate_benchmark_target(target)
    checked_profile = _profile(target, profile)
    checked_assets = _observed_assets(target, observed_assets)
    checked_rotation = _rotation(target_rotation)
    missing_rotation = [item for item in checked_rotation if item not in target.scope.assets]
    if missing_rotation:
        raise ValueError("EnvironmentProof benchmark target_rotation must stay in lab scope")
    checked_refs = _evidence_ref_tuple(evidence_refs)
    checked_reset_ref = _evidence_ref(reset_evidence_ref, "reset_evidence_ref")
    if checked_reset_ref not in checked_refs:
        raise ValueError("EnvironmentProof reset_evidence_ref must be included in evidence_refs")
    provisioning = _provisioning_payload(target)
    provisioning["target_rotation"] = list(checked_rotation)
    return EnvironmentProof(
        target_id=target.id,
        status="verified",
        profile=checked_profile,
        environment_kind="benchmark_environment",
        observed_assets=checked_assets,
        evidence_refs=checked_refs,
        reset_evidence_ref=checked_reset_ref,
        exit_gates=BENCHMARK_EXIT_GATES,
        provisioning=provisioning,
        observations=dict(observations or {}),
    )


def probe_local_container_environment(
    target: CTFTarget,
    *,
    reset_evidence_ref: str,
    profile: str,
    timeout_seconds: float = 5.0,
    body_limit_bytes: int = 4096,
) -> EnvironmentProof:
    _validate_local_container_target(target)
    checked_reset_ref = _evidence_ref(reset_evidence_ref, "reset_evidence_ref")
    observations = tuple(
        _probe_http_asset(asset, timeout_seconds=timeout_seconds, body_limit_bytes=body_limit_bytes)
        for asset in target.scope.assets
    )
    evidence_refs = tuple(_observation_evidence_ref(observation) for observation in observations) + (
        checked_reset_ref,
    )
    return verify_local_container_environment(
        target,
        observed_assets=tuple(observation["asset"] for observation in observations),
        evidence_refs=evidence_refs,
        reset_evidence_ref=checked_reset_ref,
        profile=profile,
        observations={"http": observations},
    )


def probe_vulhub_cve_environment(
    target: CTFTarget,
    *,
    reset_evidence_ref: str,
    profile: str,
    timeout_seconds: float = 5.0,
    body_limit_bytes: int = 4096,
) -> VulhubEnvironmentProof:
    proof = probe_local_container_environment(
        target,
        reset_evidence_ref=reset_evidence_ref,
        profile=profile,
        timeout_seconds=timeout_seconds,
        body_limit_bytes=body_limit_bytes,
    )
    observed_product, observed_version = _observed_vulhub_product_version(target, proof)
    if not observed_version:
        raise ValueError("Vulhub environment proof requires observed version evidence")
    applicability = validate_vulhub_exploit_applicability(
        target,
        observed_product=observed_product,
        observed_version=observed_version,
        evidence_refs=proof.evidence_refs,
        observations=proof.observations,
    )
    return VulhubEnvironmentProof(
        target_id=target.id,
        observed_product=observed_product,
        observed_version=observed_version,
        evidence_refs=proof.evidence_refs,
        exit_gates=proof.exit_gates + applicability.exit_gates,
        environment_proof=proof,
        applicability=applicability,
    )


def verify_phase_local_lab_environment(
    phase: CTFLabPhase,
    target: CTFTarget,
    *,
    observed_assets: list[str] | tuple[str, ...],
    evidence_refs: list[str] | tuple[str, ...],
    reset_evidence_ref: str,
    profile: str,
    observations: Mapping[str, Any] | None = None,
) -> PhaseEnvironmentProof:
    _validate_phase_local_lab_target(phase, target)
    proof = verify_local_container_environment(
        target,
        observed_assets=observed_assets,
        evidence_refs=evidence_refs,
        reset_evidence_ref=reset_evidence_ref,
        profile=profile,
        observations=observations,
    )
    return _phase_environment_proof(phase, target, proof)


def probe_phase_local_lab_environment(
    phase: CTFLabPhase,
    target: CTFTarget,
    *,
    reset_evidence_ref: str,
    profile: str,
    timeout_seconds: float = 5.0,
    body_limit_bytes: int = 4096,
) -> PhaseEnvironmentProof:
    _validate_phase_local_lab_target(phase, target)
    proof = probe_local_container_environment(
        target,
        reset_evidence_ref=reset_evidence_ref,
        profile=profile,
        timeout_seconds=timeout_seconds,
        body_limit_bytes=body_limit_bytes,
    )
    return _phase_environment_proof(phase, target, proof)


def _phase_environment_proof(phase: CTFLabPhase, target: CTFTarget, proof: EnvironmentProof) -> PhaseEnvironmentProof:
    return PhaseEnvironmentProof(
        phase_number=phase.number,
        phase_id=phase.id,
        target_id=target.id,
        target_family=target.target_family,
        status=proof.status,
        evidence_refs=proof.evidence_refs,
        reset_evidence_ref=proof.reset_evidence_ref,
        exit_gates=PHASE_LOCAL_LAB_EXIT_GATES,
        environment_proof=proof,
    )
