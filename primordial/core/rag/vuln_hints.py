from __future__ import annotations

from typing import Any


BLOCKED_VULN_OUTPUT_MODES = {
    "exploit_execution",
    "payload_generation",
    "real_target_attack_instructions",
    "automated_scanning",
    "action_selection",
    "scope_expansion",
    "persistence",
    "evasion",
    "credential_theft",
    "malware_behavior",
}


def vulnerability_hints_from_results(results: list[dict[str, Any]]) -> dict[str, object]:
    hints: list[dict[str, object]] = []
    rejected: list[dict[str, object]] = []
    for item in results:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        if str(metadata.get("domain") or metadata.get("corpus_type") or "") != "vuln_intel":
            rejected.append({"citation_id": item.get("citation_id"), "reason": "not vulnerability intelligence"})
            continue
        blocked = (
            set(str(value) for value in metadata.get("blocked_output_modes", []) if value)
            if isinstance(metadata.get("blocked_output_modes"), list)
            else set()
        )
        if not blocked:
            rejected.append({"citation_id": item.get("citation_id"), "reason": "missing safety block metadata"})
            continue
        hint_type = _hint_type(metadata)
        hints.append(
            {
                "hint_type": hint_type,
                "title": item.get("title") or metadata.get("cve_id") or metadata.get("vuln_id"),
                "summary": _summary(metadata),
                "citation_id": item.get("citation_id"),
                "vuln_id": metadata.get("vuln_id"),
                "cve_id": metadata.get("cve_id"),
                "aliases": metadata.get("aliases", []),
                "source_refs": metadata.get("source_refs", []),
                "allowed_output_modes": metadata.get("output_mode", []),
                "blocked_output_modes": sorted(BLOCKED_VULN_OUTPUT_MODES),
                "requires_operator_confirmation": hint_type == "defensive_exposure_review",
                "creates_executable_task": False,
                "can_expand_scope": False,
            }
        )
    return {
        "ok": True,
        "policy": "vulnerability_stream_hints_only",
        "hints": hints,
        "rejected": rejected,
    }


def _hint_type(metadata: dict[str, Any]) -> str:
    if bool(metadata.get("kev")):
        return "known_exploited_vulnerability_context"
    try:
        if float(metadata.get("epss_percentile") or 0.0) >= 0.9:
            return "epss_high_percentile_context"
    except (TypeError, ValueError):
        pass
    if str(metadata.get("cvss_severity") or "").upper() in {"HIGH", "CRITICAL"}:
        return "high_severity_vulnerability_context"
    if bool(metadata.get("fixed_version_known")):
        return "patch_prioritization_context"
    return "defensive_exposure_review"


def _summary(metadata: dict[str, Any]) -> str:
    pieces = []
    if metadata.get("cve_id"):
        pieces.append(str(metadata["cve_id"]))
    if metadata.get("cvss_severity"):
        pieces.append(f"severity={metadata['cvss_severity']}")
    if metadata.get("kev"):
        pieces.append("KEV=true")
    if metadata.get("epss_percentile") is not None:
        pieces.append(f"EPSS percentile={metadata['epss_percentile']}")
    if metadata.get("fixed_version_known"):
        pieces.append("fix available")
    return "; ".join(pieces) or "Vulnerability intelligence context is available for defensive review."
