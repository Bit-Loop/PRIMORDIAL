from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
import json
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from primordial.labs.ctf.hidden_material import normalized_hidden_material_key, reject_hidden_flag_material

SAFE_DEFAULT_INTENT = "recon_only"
LOCAL_CTF_DEFAULT_INTENT = "local_ctf_container"
ALLOWED_ENGAGEMENT_PROFILES = frozenset({"co_internal_lab", "co_hack_the_box"})
ALLOWED_WRITEUP_ACCESS_POLICIES = frozenset({"closed_book", "postmortem_only"})


@dataclass(frozen=True, slots=True)
class TargetScope:
    network: str = ""
    assets: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ResetMetadata:
    mode: str = ""
    network: str = ""
    compose_project: str = ""
    published_ports: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class ClosedBookPolicy:
    strip_paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidenceExpectations:
    required: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class VulnerabilityMetadata:
    cve_id: str = ""
    product: str = ""
    affected_versions: tuple[str, ...] = ()
    fixed_versions: tuple[str, ...] = ()
    observed_version_evidence_required: bool = False


@dataclass(frozen=True, slots=True)
class CTFTarget:
    id: str
    name: str
    platform: str
    category: str
    difficulty: str
    scope: TargetScope
    reset: ResetMetadata
    target_family: str = ""
    source_repo: str = ""
    success_condition: Mapping[str, Any] = field(default_factory=dict)
    writeup_access_policy: str = "closed_book"
    closed_book: ClosedBookPolicy = field(default_factory=ClosedBookPolicy)
    allowed_engagement_profiles: tuple[str, ...] = ("co_internal_lab",)
    mutation_policy: Mapping[str, Any] = field(default_factory=dict)
    scoreboard_ref: Mapping[str, Any] = field(default_factory=dict)
    evidence_expectations: EvidenceExpectations = field(default_factory=EvidenceExpectations)
    vulnerability: VulnerabilityMetadata = field(default_factory=VulnerabilityMetadata)
    default_intent: str = "recon_only"


def load_ctf_target_manifest(manifest: Mapping[str, Any]) -> CTFTarget:
    reject_hidden_flag_material(manifest, path="manifest", label="CTF target manifest")
    scope = _mapping(manifest.get("scope"))
    provisioning = _mapping(manifest.get("provisioning"))
    closed_book = _mapping(manifest.get("closed_book"))
    evidence = _mapping(manifest.get("evidence"))
    policy = _mapping(manifest.get("policy"))
    source = _mapping(manifest.get("source"))
    target_family = str(manifest.get("target_family", "")).strip()
    scope_assets = _text_tuple(scope.get("assets"))
    _validate_local_scope_assets(scope_assets)
    vulnerability = _vulnerability_metadata(manifest, target_family=target_family)
    default_intent = _default_intent(manifest=manifest, policy=policy)
    writeup_access_policy = _writeup_access_policy(closed_book)

    return CTFTarget(
        id=_required_text(manifest, "lab_id"),
        name=_required_text(manifest, "title"),
        platform=_required_text(manifest, "platform"),
        category=_required_text(manifest, "category"),
        difficulty=_required_text(manifest, "difficulty"),
        target_family=target_family,
        source_repo=str(source.get("repo_url", "")).strip(),
        scope=TargetScope(
            network=str(scope.get("network", "")).strip(),
            assets=scope_assets,
        ),
        reset=ResetMetadata(
            mode=str(provisioning.get("mode", "")).strip(),
            network=str(provisioning.get("network", "")).strip(),
            compose_project=str(provisioning.get("compose_project", "")).strip(),
            published_ports=_dict_tuple(provisioning.get("published_ports")),
        ),
        success_condition=_mapping(manifest.get("success_condition")),
        writeup_access_policy=writeup_access_policy,
        closed_book=ClosedBookPolicy(strip_paths=_text_tuple(closed_book.get("strip_paths"))),
        allowed_engagement_profiles=_allowed_engagement_profiles(
            manifest.get("allowed_engagement_profiles"),
            default=("co_internal_lab",),
        ),
        mutation_policy=_mapping(manifest.get("mutation")),
        scoreboard_ref=_mapping(manifest.get("ctfd")),
        evidence_expectations=EvidenceExpectations(required=_text_tuple(evidence.get("required"))),
        vulnerability=vulnerability,
        default_intent=default_intent,
    )


def load_ctf_target_manifest_file(path: str | Path) -> CTFTarget:
    manifest_path = Path(path)
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"CTF target manifest file is not valid JSON: {manifest_path}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError(f"CTF target manifest file must contain a JSON object: {manifest_path}")
    return load_ctf_target_manifest(payload)


def _mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("CTF target manifest sections must be mappings")
    return dict(value)


def _required_text(manifest: Mapping[str, Any], key: str) -> str:
    value = str(manifest.get(key, "")).strip()
    if not value:
        raise ValueError(f"CTF target manifest requires {key}")
    return value


def _default_intent(*, manifest: Mapping[str, Any], policy: Mapping[str, Any]) -> str:
    if "default_intent" not in policy and _is_local_ctf_container_manifest(manifest):
        return LOCAL_CTF_DEFAULT_INTENT
    intent = str(policy.get("default_intent", SAFE_DEFAULT_INTENT)).strip() or SAFE_DEFAULT_INTENT
    if _normalized_token(intent) != SAFE_DEFAULT_INTENT:
        raise ValueError("CTF target manifest default_intent must be recon_only")
    return SAFE_DEFAULT_INTENT


def _allowed_engagement_profiles(value: Any, *, default: tuple[str, ...]) -> tuple[str, ...]:
    profiles = tuple(_normalized_token(profile) for profile in _text_tuple(value, default=default))
    invalid = sorted(profile for profile in profiles if profile not in ALLOWED_ENGAGEMENT_PROFILES)
    if invalid:
        raise ValueError("CTF target manifest allowed_engagement_profiles must use explicit co_* profiles")
    return profiles


def _writeup_access_policy(closed_book: Mapping[str, Any]) -> str:
    policy = _normalized_token(str(closed_book.get("writeup_access_policy", "closed_book")))
    policy = policy or "closed_book"
    if policy not in ALLOWED_WRITEUP_ACCESS_POLICIES:
        raise ValueError("CTF target manifest writeup_access_policy must be closed_book or postmortem_only")
    return policy


def _vulnerability_metadata(manifest: Mapping[str, Any], *, target_family: str) -> VulnerabilityMetadata:
    vulnerability = _mapping(manifest.get("vulnerability"))
    if not vulnerability and target_family != "vulhub_cve_labs":
        return VulnerabilityMetadata()
    cve_id = str(vulnerability.get("cve_id", "")).strip().upper()
    product = str(vulnerability.get("product", "")).strip()
    affected_versions = _text_tuple(vulnerability.get("affected_versions"))
    fixed_versions = _text_tuple(vulnerability.get("fixed_versions"))
    if not cve_id.startswith("CVE-"):
        raise ValueError("CTF target manifest vulnerability requires cve_id")
    if not product:
        raise ValueError("CTF target manifest vulnerability requires product")
    if not affected_versions:
        raise ValueError("CTF target manifest vulnerability requires affected_versions")
    if not fixed_versions:
        raise ValueError("CTF target manifest vulnerability requires fixed_versions")
    return VulnerabilityMetadata(
        cve_id=cve_id,
        product=product,
        affected_versions=affected_versions,
        fixed_versions=fixed_versions,
        observed_version_evidence_required=_bool(
            vulnerability.get("observed_version_evidence_required"),
            default=target_family == "vulhub_cve_labs",
        ),
    )


def _normalized_token(value: str) -> str:
    return normalized_hidden_material_key(value)


def _text_tuple(value: Any, *, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    if value is None:
        return default
    if not isinstance(value, list | tuple):
        raise ValueError("CTF target manifest list fields must be lists")
    return tuple(str(item).strip() for item in value if str(item).strip())


def _validate_local_scope_assets(assets: tuple[str, ...]) -> None:
    for asset in assets:
        host = _asset_host(asset)
        if host and not _is_local_lab_host(host):
            raise ValueError(f"CTF target manifest scope assets must stay in local lab scope: {asset}")


def _asset_host(asset: str) -> str:
    parsed = urlparse(asset if "://" in asset else f"//{asset}")
    host = parsed.hostname or ""
    return host.strip("[]").lower()


def _is_local_lab_host(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    if host.endswith((".localhost", ".local")):
        return True
    try:
        address = ip_address(host)
    except ValueError:
        return "." not in host
    return address.is_private or address.is_loopback or address.is_link_local


def _dict_tuple(value: Any) -> tuple[dict[str, Any], ...]:
    if value is None:
        return ()
    if not isinstance(value, list | tuple):
        raise ValueError("CTF target manifest published_ports must be a list")
    ports: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("CTF target manifest published_ports entries must be mappings")
        ports.append(dict(item))
    return tuple(ports)


def _bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError("CTF target manifest boolean fields must be booleans")
    return value


def _is_local_ctf_container_manifest(manifest: Mapping[str, Any]) -> bool:
    provisioning = _mapping(manifest.get("provisioning"))
    scope = _mapping(manifest.get("scope"))
    mode = _normalized_token(str(provisioning.get("mode", manifest.get("platform", ""))))
    return bool(manifest.get("lab_id")) and mode in {"docker", "podman", "container"} and bool(_text_tuple(scope.get("assets")))
