from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from primordial.labs.ctf.applicability import ExploitApplicabilityResult, validate_vulhub_exploit_applicability
from primordial.labs.ctf.hidden_material import normalized_hidden_material_key, reject_hidden_flag_material
from primordial.labs.ctf.targets import CTFTarget


LOCAL_CONTAINER_MODES = frozenset({"container", "docker", "podman"})
LOCAL_CONTAINER_EXIT_GATES = ("local_container_environment_verified",)
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


def _validate_local_container_target(target: CTFTarget) -> None:
    mode = _token(target.reset.mode or target.platform)
    if mode not in LOCAL_CONTAINER_MODES:
        raise ValueError("EnvironmentProof target must use local container provisioning")
    if not target.scope.assets:
        raise ValueError("EnvironmentProof local container target requires scoped assets")
    if not any((target.reset.network, target.reset.compose_project, target.reset.published_ports)):
        raise ValueError("EnvironmentProof local container target requires reset metadata")


def _profile(target: CTFTarget, profile: str) -> str:
    checked = str(profile).strip()
    if not checked:
        raise ValueError("EnvironmentProof requires profile")
    if checked not in target.allowed_engagement_profiles:
        raise ValueError("EnvironmentProof profile must be allowed by target manifest")
    return checked


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
