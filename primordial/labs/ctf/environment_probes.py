from __future__ import annotations

from collections.abc import Callable
import hashlib
import subprocess
from typing import Any, Mapping

from primordial.labs.ctf.environment import (
    EnvironmentProof,
    verify_benchmark_environment,
    verify_local_ad_lab_environment,
    verify_local_cluster_environment,
    verify_sandbox_cloud_environment,
)
from primordial.labs.ctf.environment_helpers import (
    account_id as _account_id,
    domain as _domain,
    evidence_ref as _evidence_ref,
    probe_http_asset as _probe_http_asset,
    regions as _regions,
    rotation as _rotation,
    namespace as _namespace,
)
from primordial.labs.ctf.hidden_material import reject_hidden_flag_material
from primordial.labs.ctf.targets import CTFTarget

CommandRunner = Callable[[tuple[str, ...]], Mapping[str, Any] | str]


def probe_local_cluster_environment(
    target: CTFTarget,
    *,
    namespace: str,
    reset_evidence_ref: str,
    profile: str,
    command_runner: CommandRunner | None = None,
) -> EnvironmentProof:
    checked_namespace = _namespace(namespace)
    commands = (
        ("kubectl", "get", "namespace", checked_namespace, "-o", "json"),
        ("kubectl", "-n", checked_namespace, "get", "all", "-o", "json"),
    )
    observations = tuple(_run_probe_command(command, command_runner=command_runner) for command in commands)
    checked_reset_ref = _evidence_ref(reset_evidence_ref, "reset_evidence_ref")
    evidence_refs = tuple(_command_evidence_ref(observation) for observation in observations) + (checked_reset_ref,)
    return verify_local_cluster_environment(
        target,
        namespace=checked_namespace,
        observed_assets=target.scope.assets,
        evidence_refs=evidence_refs,
        reset_evidence_ref=checked_reset_ref,
        profile=profile,
        observations={"commands": observations},
    )


def probe_local_ad_lab_environment(
    target: CTFTarget,
    *,
    domain: str,
    reset_evidence_ref: str,
    profile: str,
    command_runner: CommandRunner | None = None,
) -> EnvironmentProof:
    checked_domain = _domain(domain)
    network = str(target.scope.network or target.reset.network or checked_domain).strip()
    commands: list[tuple[str, ...]] = [("virsh", "net-info", network)]
    commands.extend(("nmap", "-Pn", "-p", "88,389,445,5985", asset) for asset in target.scope.assets)
    observations = tuple(_run_probe_command(command, command_runner=command_runner) for command in commands)
    checked_reset_ref = _evidence_ref(reset_evidence_ref, "reset_evidence_ref")
    evidence_refs = tuple(_command_evidence_ref(observation) for observation in observations) + (checked_reset_ref,)
    return verify_local_ad_lab_environment(
        target,
        domain=checked_domain,
        observed_assets=target.scope.assets,
        evidence_refs=evidence_refs,
        reset_evidence_ref=checked_reset_ref,
        profile=profile,
        observations={"commands": observations},
    )


def probe_localstack_cloud_environment(
    target: CTFTarget,
    *,
    account_id: str,
    regions: list[str] | tuple[str, ...],
    reset_evidence_ref: str,
    profile: str,
    endpoint_url: str = "http://127.0.0.1:4566",
    command_runner: CommandRunner | None = None,
) -> EnvironmentProof:
    checked_account_id = _account_id(account_id)
    checked_regions = _regions(regions)
    endpoint = str(endpoint_url or "").strip()
    if not endpoint:
        raise ValueError("EnvironmentProof requires LocalStack endpoint_url")
    commands = (
        ("aws", "--endpoint-url", endpoint, "sts", "get-caller-identity"),
        ("aws", "--endpoint-url", endpoint, "s3", "ls"),
    )
    observations = tuple(_run_probe_command(command, command_runner=command_runner) for command in commands)
    checked_reset_ref = _evidence_ref(reset_evidence_ref, "reset_evidence_ref")
    evidence_refs = tuple(_command_evidence_ref(observation) for observation in observations) + (checked_reset_ref,)
    return verify_sandbox_cloud_environment(
        target,
        account_id=checked_account_id,
        regions=checked_regions,
        observed_assets=target.scope.assets,
        evidence_refs=evidence_refs,
        reset_evidence_ref=checked_reset_ref,
        profile=profile,
        observations={"commands": observations, "endpoint_url": endpoint},
    )


def probe_benchmark_environment(
    target: CTFTarget,
    *,
    reset_evidence_ref: str,
    profile: str,
    target_rotation: list[str] | tuple[str, ...] | None = None,
    command_runner: CommandRunner | None = None,
    timeout_seconds: float = 5.0,
    body_limit_bytes: int = 4096,
) -> EnvironmentProof:
    rotation = _rotation(tuple(target_rotation or target.scope.assets))
    observations: tuple[Mapping[str, Any], ...]
    if command_runner is None:
        non_http_assets = [asset for asset in rotation if not str(asset).startswith(("http://", "https://"))]
        if non_http_assets:
            raise ValueError("EnvironmentProof benchmark live probe requires command_runner for non-HTTP targets")
        observations = tuple(
            _probe_http_asset(asset, timeout_seconds=timeout_seconds, body_limit_bytes=body_limit_bytes)
            for asset in rotation
        )
    else:
        observations = tuple(
            _run_probe_command(("curl", "-fsS", asset), command_runner=command_runner)
            for asset in rotation
        )
    checked_reset_ref = _evidence_ref(reset_evidence_ref, "reset_evidence_ref")
    evidence_refs = tuple(_command_evidence_ref(observation) for observation in observations) + (checked_reset_ref,)
    return verify_benchmark_environment(
        target,
        observed_assets=target.scope.assets,
        evidence_refs=evidence_refs,
        reset_evidence_ref=checked_reset_ref,
        profile=profile,
        target_rotation=rotation,
        observations={"benchmark": observations},
    )


def _run_probe_command(
    command: tuple[str, ...],
    *,
    command_runner: CommandRunner | None,
) -> dict[str, Any]:
    if command_runner is None:
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        raw_result: Mapping[str, Any] = {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    else:
        result = command_runner(command)
        raw_result = {"returncode": 0, "stdout": result, "stderr": ""} if isinstance(result, str) else result
    returncode = int(raw_result.get("returncode", 0))
    stdout = str(raw_result.get("stdout", ""))
    stderr = str(raw_result.get("stderr", ""))
    if returncode != 0:
        raise ValueError(f"EnvironmentProof live probe command failed: {' '.join(command)}")
    observation = {
        "command": list(command),
        "returncode": returncode,
        "stdout_sha256": _sha256_text(stdout),
        "stderr_sha256": _sha256_text(stderr),
        "stdout_bytes": len(stdout.encode("utf-8")),
        "stderr_bytes": len(stderr.encode("utf-8")),
    }
    reject_hidden_flag_material(observation, path="ctf_environment_command_probe", label="EnvironmentProof")
    return observation


def _command_evidence_ref(observation: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(
        (
            " ".join(str(item) for item in observation.get("command", ()))
            + "|"
            + str(observation.get("stdout_sha256", ""))
            + "|"
            + str(observation.get("stderr_sha256", ""))
        ).encode("utf-8")
    ).hexdigest()[:16]
    return f"evidence:live-probe:{digest}"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
