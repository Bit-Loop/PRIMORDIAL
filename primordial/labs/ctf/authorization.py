from __future__ import annotations

from typing import Any
from urllib import parse
import ipaddress

from primordial.core.domain.enums import PolicyVerdict, ScopeProfile, TaskKind
from primordial.labs.ctf.phases import load_ctf_lab_phase_catalog


ACTIVE_CTF_INTENT = "ctf_solve_autonomous_local"
RUNNABLE_PHASE_STATUSES = frozenset({"ready_for_review", "complete"})


def local_ctf_authorization_error(
    *,
    target: object,
    task: object | None = None,
    store: object | None = None,
    active_intent_id: str = "",
    phase_catalog_path: object = "catalog/labs/ctf_lab_phases.yaml",
) -> str:
    metadata = getattr(target, "metadata", {}) if target is not None else {}
    if not isinstance(metadata, dict):
        return "target metadata is not available"
    if not _is_ctf_identity(metadata):
        return "target is not marked as a local autonomous CTF lab"
    if not _is_local_or_private_target(target, store=store):
        return "target scope is not local/private"
    phase_number = _phase_number(metadata)
    if phase_number is not None and not _phase_is_runnable(
        phase_number,
        metadata=metadata,
        phase_catalog_path=phase_catalog_path,
    ):
        return "lab phase is not ready and no explicit in-progress override is recorded"
    if not _has_environment_proof(metadata):
        return "local CTF environment proof is missing"
    if not _has_active_ctf_intent(task, metadata=metadata, active_intent_id=active_intent_id):
        return "active intent is not ctf_solve_autonomous_local"
    if store is not None and not _has_allow_policy_decision(store, target=target, task=task):
        return "allow policy decision is missing"
    return ""


def is_local_ctf_authorized(**kwargs: Any) -> bool:
    return local_ctf_authorization_error(**kwargs) == ""


def _is_ctf_identity(metadata: dict[str, Any]) -> bool:
    return (
        metadata.get("local_ctf_autonomous") is True
        and str(metadata.get("ctf_completion_indicator", "")).strip() == "autonomous_flags"
    )


def _is_local_or_private_target(target: object, *, store: object | None) -> bool:
    profile = getattr(target, "profile", None)
    if profile == ScopeProfile.CORPUS:
        return False
    assets = []
    if hasattr(target, "assets"):
        assets = list(getattr(target, "assets") or [])
    if store is not None and hasattr(store, "list_scope_assets") and getattr(target, "id", None):
        try:
            assets.extend(item.asset for item in store.list_scope_assets(target.id))
        except Exception:
            pass
    metadata = getattr(target, "metadata", {})
    if isinstance(metadata, dict):
        for key in ("ctf_target_url", "ctf_service_urls"):
            value = metadata.get(key)
            if isinstance(value, str):
                assets.append(value)
            elif isinstance(value, (list, tuple)):
                assets.extend(str(item) for item in value)
    return bool(assets) and all(_is_local_or_private_asset(str(asset)) for asset in assets)


def _is_local_or_private_asset(value: str) -> bool:
    if value.startswith(("kubernetes://", "docker://", "compose://", "localstack://")):
        return True
    parsed = parse.urlsplit(value)
    host = parsed.hostname
    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host.endswith(".local") or host.endswith(".internal")
    return address.is_private or address.is_loopback or address.is_link_local


def _phase_number(metadata: dict[str, Any]) -> int | None:
    try:
        value = int(metadata.get("ctf_phase", metadata.get("phase", "")))
    except (TypeError, ValueError):
        return None
    return value if 0 <= value <= 8 else None


def _phase_is_runnable(phase: int, *, metadata: dict[str, Any], phase_catalog_path: object) -> bool:
    if metadata.get("ctf_allow_in_progress") is True:
        return True
    try:
        record = load_ctf_lab_phase_catalog(phase_catalog_path).phase(phase)
    except Exception:
        return False
    return record.status in RUNNABLE_PHASE_STATUSES


def _has_environment_proof(metadata: dict[str, Any]) -> bool:
    value = str(metadata.get("ctf_environment_proof_ref") or "").strip()
    return value.startswith("evidence:")


def _has_active_ctf_intent(task: object | None, *, metadata: dict[str, Any], active_intent_id: str) -> bool:
    candidates = {str(active_intent_id or "").strip()}
    task_metadata = getattr(task, "metadata", {}) if task is not None else {}
    if isinstance(task_metadata, dict):
        candidates.add(str(task_metadata.get("operator_intent_id") or "").strip())
        candidates.add(str(task_metadata.get("active_intent") or "").strip())
    candidates.add(str(metadata.get("ctf_active_intent") or metadata.get("active_intent") or "").strip())
    return ACTIVE_CTF_INTENT in candidates


def _has_allow_policy_decision(store: object, *, target: object, task: object | None) -> bool:
    target_id = getattr(target, "id", None)
    task_id = getattr(task, "id", None) if task is not None else None
    decisions = []
    if hasattr(store, "list_policy_decisions"):
        if task_id:
            decisions.extend(store.list_policy_decisions(task_id=task_id, limit=20))
        if target_id:
            decisions.extend(store.list_policy_decisions(target_id=target_id, limit=20))
    return any(
        getattr(decision, "verdict", None) == PolicyVerdict.ALLOW
        and (
            getattr(decision, "action_kind", "") == TaskKind.CTF_FLAG_CAPTURE.value
            or str(getattr(decision, "metadata", {}).get("primitive_hint", "")) == "ctf-flag-capture"
        )
        for decision in decisions
    )
