from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from primordial.labs.ctf.applicability import ExploitApplicabilityResult, validate_vulhub_exploit_applicability
from primordial.labs.ctf.hidden_material import normalized_hidden_material_key, reject_hidden_flag_material
from primordial.labs.ctf.phases import CTFLabPhase
from primordial.labs.ctf.targets import CTFTarget


LOCAL_CONTAINER_MODES = frozenset({"container", "docker", "podman"})
LOCAL_CLUSTER_MODES = frozenset({"kubernetes", "kind", "k3d", "minikube", "local_cluster"})
LOCAL_AD_LAB_MODES = frozenset({"active_directory", "ad_lab", "goad", "goad_light"})
SANDBOX_CLOUD_MODES = frozenset({"cloud", "sandbox_cloud", "terraform"})
LOCAL_CONTAINER_EXIT_GATES = ("local_container_environment_verified",)
LOCAL_CLUSTER_EXIT_GATES = ("local_cluster_environment_verified",)
LOCAL_AD_LAB_EXIT_GATES = ("local_ad_lab_environment_verified",)
SANDBOX_CLOUD_EXIT_GATES = ("sandbox_cloud_account_verified",)
PHASE_LOCAL_LAB_EXIT_GATES = ("local_lab_environment_verified",)
_SERVER_PRODUCT_VERSION = re.compile(r"(?P<product>[A-Za-z][A-Za-z0-9_.-]*)/(?P<version>[0-9][A-Za-z0-9_.-]*)")


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


def _validate_local_container_target(target: CTFTarget) -> None:
    mode = _token(target.reset.mode or target.platform)
    if mode not in LOCAL_CONTAINER_MODES:
        raise ValueError("EnvironmentProof target must use local container provisioning")
    if not target.scope.assets:
        raise ValueError("EnvironmentProof local container target requires scoped assets")
    if not any((target.reset.network, target.reset.compose_project, target.reset.published_ports)):
        raise ValueError("EnvironmentProof local container target requires reset metadata")


def _validate_local_cluster_target(target: CTFTarget) -> None:
    mode = _token(target.reset.mode or target.platform)
    if mode not in LOCAL_CLUSTER_MODES:
        raise ValueError("EnvironmentProof target must use local cluster provisioning")
    if not target.scope.assets:
        raise ValueError("EnvironmentProof local cluster target requires scoped assets")
    if not (target.scope.network or target.reset.network):
        raise ValueError("EnvironmentProof local cluster target requires cluster or network metadata")


def _validate_local_ad_lab_target(target: CTFTarget) -> None:
    mode = _token(target.reset.mode or target.platform)
    if mode not in LOCAL_AD_LAB_MODES:
        raise ValueError("EnvironmentProof target must use local AD lab provisioning")
    if not target.scope.assets:
        raise ValueError("EnvironmentProof local AD lab target requires scoped assets")
    if not (target.scope.network or target.reset.network):
        raise ValueError("EnvironmentProof local AD lab target requires domain metadata")


def _validate_sandbox_cloud_target(target: CTFTarget) -> None:
    mode = _token(target.reset.mode or target.platform)
    if mode not in SANDBOX_CLOUD_MODES:
        raise ValueError("EnvironmentProof target must use sandbox cloud provisioning")
    if not target.scope.assets:
        raise ValueError("EnvironmentProof sandbox cloud target requires scoped assets")
    if not (target.scope.network or target.reset.network):
        raise ValueError("EnvironmentProof sandbox cloud target requires account boundary metadata")


def _namespace(value: str) -> str:
    namespace = str(value or "").strip()
    if not namespace:
        raise ValueError("EnvironmentProof requires namespace")
    if namespace in {"*", "all", "default", "kube-node-lease", "kube-public", "kube-system"}:
        raise ValueError("EnvironmentProof namespace must be dedicated to the local lab")
    return namespace


def _domain(value: str) -> str:
    domain = str(value or "").strip().lower()
    if not domain or "." not in domain:
        raise ValueError("EnvironmentProof requires local AD domain")
    return domain


def _account_id(value: str) -> str:
    account_id = str(value or "").strip()
    if len(account_id) != 12 or not account_id.isdigit():
        raise ValueError("EnvironmentProof requires 12-digit sandbox cloud account_id")
    return account_id


def _regions(value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("EnvironmentProof regions must be a list or tuple")
    regions = tuple(str(item or "").strip() for item in value if str(item or "").strip())
    if not regions:
        raise ValueError("EnvironmentProof requires at least one sandbox cloud region")
    if len(set(regions)) != len(regions):
        raise ValueError("EnvironmentProof duplicate sandbox cloud region")
    return regions


def _profile(target: CTFTarget, profile: str) -> str:
    checked = str(profile).strip()
    if not checked:
        raise ValueError("EnvironmentProof requires profile")
    if checked not in target.allowed_engagement_profiles:
        raise ValueError("EnvironmentProof profile must be allowed by target manifest")
    return checked


def _validate_phase_local_lab_target(phase: CTFLabPhase, target: CTFTarget) -> None:
    if "local_lab_environment_verified" not in phase.exit_gates:
        raise ValueError("Phase environment proof requires local_lab_environment_verified exit gate")
    if target.target_family not in phase.target_families:
        raise ValueError("Phase environment proof target_family must be allowed by phase")
    if not phase.environment_proof_required:
        raise ValueError("Phase environment proof requires environment_proof_required phase")


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


def _observed_assets(target: CTFTarget, value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    assets = _text_tuple(value, label="observed_assets")
    if set(assets) != set(target.scope.assets):
        raise ValueError("EnvironmentProof observed_assets must match target scoped assets")
    return tuple(asset for asset in target.scope.assets if asset in assets)


def _evidence_ref_tuple(value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    refs = tuple(_evidence_ref(item, "evidence_refs entry") for item in _text_tuple(value, label="evidence_refs"))
    if not refs:
        raise ValueError("EnvironmentProof requires evidence_refs")
    if len(set(refs)) != len(refs):
        raise ValueError("EnvironmentProof duplicate evidence_refs entry")
    return refs


def _evidence_ref(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"EnvironmentProof requires {name}")
    if not text.startswith("evidence:"):
        raise ValueError(f"EnvironmentProof {name} must use evidence:<id>")
    return text


def _text_tuple(value: list[str] | tuple[str, ...], *, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"EnvironmentProof {label} must be a list or tuple")
    return tuple(str(item).strip() for item in value if str(item).strip())


def _provisioning_payload(target: CTFTarget) -> dict[str, Any]:
    return {
        "mode": target.reset.mode,
        "network": target.reset.network,
        "compose_project": target.reset.compose_project,
        "published_ports": [dict(item) for item in target.reset.published_ports],
    }


def _probe_http_asset(asset: str, *, timeout_seconds: float, body_limit_bytes: int) -> dict[str, Any]:
    request = Request(asset, headers={"User-Agent": "PRIMORDIAL-ctf-environment-probe/1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            status_code = int(getattr(response, "status", response.getcode()))
            body = response.read(max(body_limit_bytes, 0) + 1)
            content_type = response.headers.get("Content-Type", "")
            server_banner = response.headers.get("Server", "")
    except HTTPError as exc:
        exc.close()
        raise ValueError(f"EnvironmentProof asset did not return healthy HTTP response: {asset}") from exc
    except URLError as exc:
        raise ValueError(f"EnvironmentProof asset did not return healthy HTTP response: {asset}") from exc
    if status_code < 200 or status_code >= 400:
        raise ValueError(f"EnvironmentProof asset did not return healthy HTTP response: {asset}")
    body = body[: max(body_limit_bytes, 0)]
    observation = {
        "asset": asset,
        "status_code": status_code,
        "content_type": str(content_type).strip(),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_bytes_sampled": len(body),
    }
    _add_server_banner_observation(observation, server_banner)
    reject_hidden_flag_material(observation, path="ctf_environment_probe", label="EnvironmentProof")
    return observation


def _add_server_banner_observation(observation: dict[str, Any], server_banner: str) -> None:
    banner = str(server_banner or "").strip()
    if not banner:
        return
    observation["server_banner_sha256"] = hashlib.sha256(banner.encode("utf-8")).hexdigest()
    match = _SERVER_PRODUCT_VERSION.search(banner)
    if match:
        observation["server_product_token"] = match.group("product").strip()
        observation["server_version"] = match.group("version").strip()


def _observed_vulhub_product_version(target: CTFTarget, proof: EnvironmentProof) -> tuple[str, str]:
    observations = proof.observations.get("http", ())
    if not isinstance(observations, tuple | list):
        return target.vulnerability.product, ""
    expected_product = target.vulnerability.product
    expected_token = _token(expected_product)
    for observation in observations:
        if not isinstance(observation, Mapping):
            continue
        product_token = str(observation.get("server_product_token", "")).strip()
        version = str(observation.get("server_version", "")).strip()
        if not product_token or not version:
            continue
        normalized_product = _token(product_token)
        if normalized_product in expected_token or expected_token in normalized_product:
            return expected_product, version
    return expected_product, ""


def _observation_evidence_ref(observation: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(
        (
            str(observation.get("asset", ""))
            + "|"
            + str(observation.get("status_code", ""))
            + "|"
            + str(observation.get("body_sha256", ""))
        ).encode("utf-8")
    ).hexdigest()[:16]
    return f"evidence:local-container:{digest}"


def _plain_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): [dict(item) if isinstance(item, Mapping) else item for item in child]
        if isinstance(child, list)
        else child
        for key, child in value.items()
    }


def _token(value: str) -> str:
    return normalized_hidden_material_key(value)
