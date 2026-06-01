from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from primordial.labs.ctf.hidden_material import normalized_hidden_material_key, reject_hidden_flag_material
from primordial.labs.ctf.phases import CTFLabPhase
from primordial.labs.ctf.targets import CTFTarget


LOCAL_CONTAINER_MODES = frozenset({"container", "docker", "podman"})
LOCAL_CLUSTER_MODES = frozenset({"kubernetes", "kind", "k3d", "minikube", "local_cluster"})
LOCAL_AD_LAB_MODES = frozenset({"active_directory", "ad_lab", "goad", "goad_light"})
SANDBOX_CLOUD_MODES = frozenset({"cloud", "sandbox_cloud", "terraform"})
BENCHMARK_MODES = frozenset({"benchmark", "benchmark_fixture", "ctf_benchmark"})
LOCAL_CONTAINER_EXIT_GATES = ("local_container_environment_verified",)
LOCAL_CLUSTER_EXIT_GATES = ("local_cluster_environment_verified",)
LOCAL_AD_LAB_EXIT_GATES = ("local_ad_lab_environment_verified",)
SANDBOX_CLOUD_EXIT_GATES = ("sandbox_cloud_account_verified",)
BENCHMARK_EXIT_GATES = ("benchmark_environment_verified",)
PHASE_LOCAL_LAB_EXIT_GATES = ("local_lab_environment_verified",)
_SERVER_PRODUCT_VERSION = re.compile(r"(?P<product>[A-Za-z][A-Za-z0-9_.-]*)/(?P<version>[0-9][A-Za-z0-9_.-]*)")


def validate_local_container_target(target: CTFTarget) -> None:
    mode = token(target.reset.mode or target.platform)
    if mode not in LOCAL_CONTAINER_MODES:
        raise ValueError("EnvironmentProof target must use local container provisioning")
    if not target.scope.assets:
        raise ValueError("EnvironmentProof local container target requires scoped assets")
    if not any((target.reset.network, target.reset.compose_project, target.reset.published_ports)):
        raise ValueError("EnvironmentProof local container target requires reset metadata")


def validate_local_cluster_target(target: CTFTarget) -> None:
    mode = token(target.reset.mode or target.platform)
    if mode not in LOCAL_CLUSTER_MODES:
        raise ValueError("EnvironmentProof target must use local cluster provisioning")
    if not target.scope.assets:
        raise ValueError("EnvironmentProof local cluster target requires scoped assets")
    if not (target.scope.network or target.reset.network):
        raise ValueError("EnvironmentProof local cluster target requires cluster or network metadata")


def validate_local_ad_lab_target(target: CTFTarget) -> None:
    mode = token(target.reset.mode or target.platform)
    if mode not in LOCAL_AD_LAB_MODES:
        raise ValueError("EnvironmentProof target must use local AD lab provisioning")
    if not target.scope.assets:
        raise ValueError("EnvironmentProof local AD lab target requires scoped assets")
    if not (target.scope.network or target.reset.network):
        raise ValueError("EnvironmentProof local AD lab target requires domain metadata")


def validate_sandbox_cloud_target(target: CTFTarget) -> None:
    mode = token(target.reset.mode or target.platform)
    if mode not in SANDBOX_CLOUD_MODES:
        raise ValueError("EnvironmentProof target must use sandbox cloud provisioning")
    if not target.scope.assets:
        raise ValueError("EnvironmentProof sandbox cloud target requires scoped assets")
    if not (target.scope.network or target.reset.network):
        raise ValueError("EnvironmentProof sandbox cloud target requires account boundary metadata")


def validate_benchmark_target(target: CTFTarget) -> None:
    mode = token(target.reset.mode or target.platform)
    if mode not in BENCHMARK_MODES:
        raise ValueError("EnvironmentProof target must use benchmark provisioning")
    if len(target.scope.assets) < 2:
        raise ValueError("EnvironmentProof benchmark target requires at least two scoped assets")
    if not (target.scope.network or target.reset.network):
        raise ValueError("EnvironmentProof benchmark target requires rotation metadata")


def namespace(value: str) -> str:
    checked = str(value or "").strip()
    if not checked:
        raise ValueError("EnvironmentProof requires namespace")
    if checked in {"*", "all", "default", "kube-node-lease", "kube-public", "kube-system"}:
        raise ValueError("EnvironmentProof namespace must be dedicated to the local lab")
    return checked


def domain(value: str) -> str:
    checked = str(value or "").strip().lower()
    if not checked or "." not in checked:
        raise ValueError("EnvironmentProof requires local AD domain")
    return checked


def account_id(value: str) -> str:
    checked = str(value or "").strip()
    if len(checked) != 12 or not checked.isdigit():
        raise ValueError("EnvironmentProof requires 12-digit sandbox cloud account_id")
    return checked


def regions(value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("EnvironmentProof regions must be a list or tuple")
    checked = tuple(str(item or "").strip() for item in value if str(item or "").strip())
    if not checked:
        raise ValueError("EnvironmentProof requires at least one sandbox cloud region")
    if len(set(checked)) != len(checked):
        raise ValueError("EnvironmentProof duplicate sandbox cloud region")
    return checked


def rotation(value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("EnvironmentProof target_rotation must be a list or tuple")
    checked = tuple(str(item or "").strip() for item in value if str(item or "").strip())
    if len(checked) < 2:
        raise ValueError("EnvironmentProof target_rotation requires at least two targets")
    if len(set(checked)) != len(checked):
        raise ValueError("EnvironmentProof duplicate target_rotation entry")
    return checked


def profile(target: CTFTarget, value: str) -> str:
    checked = str(value).strip()
    if not checked:
        raise ValueError("EnvironmentProof requires profile")
    if checked not in target.allowed_engagement_profiles:
        raise ValueError("EnvironmentProof profile must be allowed by target manifest")
    return checked


def validate_phase_local_lab_target(phase: CTFLabPhase, target: CTFTarget) -> None:
    if "local_lab_environment_verified" not in phase.exit_gates:
        raise ValueError("Phase environment proof requires local_lab_environment_verified exit gate")
    if target.target_family not in phase.target_families:
        raise ValueError("Phase environment proof target_family must be allowed by phase")
    if not phase.environment_proof_required:
        raise ValueError("Phase environment proof requires environment_proof_required phase")


def observed_assets(target: CTFTarget, value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    assets = text_tuple(value, label="observed_assets")
    if set(assets) != set(target.scope.assets):
        raise ValueError("EnvironmentProof observed_assets must match target scoped assets")
    return tuple(asset for asset in target.scope.assets if asset in assets)


def evidence_ref_tuple(value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    refs = tuple(evidence_ref(item, "evidence_refs entry") for item in text_tuple(value, label="evidence_refs"))
    if not refs:
        raise ValueError("EnvironmentProof requires evidence_refs")
    if len(set(refs)) != len(refs):
        raise ValueError("EnvironmentProof duplicate evidence_refs entry")
    return refs


def evidence_ref(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"EnvironmentProof requires {name}")
    if not text.startswith("evidence:"):
        raise ValueError(f"EnvironmentProof {name} must use evidence:<id>")
    return text


def text_tuple(value: list[str] | tuple[str, ...], *, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"EnvironmentProof {label} must be a list or tuple")
    return tuple(str(item).strip() for item in value if str(item).strip())


def provisioning_payload(target: CTFTarget) -> dict[str, Any]:
    return {
        "mode": target.reset.mode,
        "network": target.reset.network,
        "compose_project": target.reset.compose_project,
        "published_ports": [dict(item) for item in target.reset.published_ports],
    }


def probe_http_asset(asset: str, *, timeout_seconds: float, body_limit_bytes: int) -> dict[str, Any]:
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
    add_server_banner_observation(observation, server_banner)
    reject_hidden_flag_material(observation, path="ctf_environment_probe", label="EnvironmentProof")
    return observation


def add_server_banner_observation(observation: dict[str, Any], server_banner: str) -> None:
    banner = str(server_banner or "").strip()
    if not banner:
        return
    observation["server_banner_sha256"] = hashlib.sha256(banner.encode("utf-8")).hexdigest()
    match = _SERVER_PRODUCT_VERSION.search(banner)
    if match:
        observation["server_product_token"] = match.group("product").strip()
        observation["server_version"] = match.group("version").strip()


def observed_vulhub_product_version(target: CTFTarget, proof: Any) -> tuple[str, str]:
    observations = proof.observations.get("http", ())
    if not isinstance(observations, tuple | list):
        return target.vulnerability.product, ""
    expected_product = target.vulnerability.product
    expected_token = token(expected_product)
    for observation in observations:
        if not isinstance(observation, Mapping):
            continue
        product_token = str(observation.get("server_product_token", "")).strip()
        version = str(observation.get("server_version", "")).strip()
        if not product_token or not version:
            continue
        normalized_product = token(product_token)
        if normalized_product in expected_token or expected_token in normalized_product:
            return expected_product, version
    return expected_product, ""


def observation_evidence_ref(observation: Mapping[str, Any]) -> str:
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


def plain_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): [dict(item) if isinstance(item, Mapping) else item for item in child]
        if isinstance(child, list)
        else child
        for key, child in value.items()
    }


def token(value: str) -> str:
    return normalized_hidden_material_key(value)
