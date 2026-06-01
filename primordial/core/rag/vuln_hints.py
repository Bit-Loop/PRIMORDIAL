from __future__ import annotations

from typing import Any

from primordial.core.context.normalization import metadata_bool_value, metadata_list_value, metadata_value


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

REQUIRED_VULN_BLOCKED_OUTPUT_MODES = {
    "exploit_execution",
    "action_selection",
    "scope_expansion",
}


def vulnerability_hints_from_results(results: list[dict[str, Any]]) -> dict[str, object]:
    hints: list[dict[str, object]] = []
    rejected: list[dict[str, object]] = []
    for item in results:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        if str(metadata_value(metadata, "domain") or metadata_value(metadata, "corpus_type") or "") != "vuln_intel":
            rejected.append({"citation_id": _diagnostic_citation_id(item), "reason": "not vulnerability intelligence"})
            continue
        blocked = _blocked_output_modes(metadata)
        if not blocked:
            rejected.append({"citation_id": _diagnostic_citation_id(item), "reason": "missing safety block metadata"})
            continue
        if not REQUIRED_VULN_BLOCKED_OUTPUT_MODES.issubset(blocked):
            rejected.append(
                {"citation_id": _diagnostic_citation_id(item), "reason": "missing required safety block metadata"}
            )
            continue
        citation_id = _rag_citation_id(item)
        if not citation_id:
            rejected.append({"citation_id": _diagnostic_citation_id(item), "reason": "missing rag citation"})
            continue
        hint_type = _hint_type(metadata)
        hints.append(
            {
                "hint_type": hint_type,
                "title": item.get("title") or metadata_value(metadata, "cve_id") or metadata_value(metadata, "vuln_id"),
                "summary": _summary(metadata),
                "citation_id": citation_id,
                "vuln_id": metadata_value(metadata, "vuln_id"),
                "cve_id": metadata_value(metadata, "cve_id"),
                "aliases": metadata_list_value(metadata, "aliases"),
                "source_refs": metadata_list_value(metadata, "source_refs"),
                "allowed_output_modes": _safe_output_modes(metadata),
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
    if metadata_bool_value(metadata, "kev"):
        return "known_exploited_vulnerability_context"
    try:
        if float(metadata_value(metadata, "epss_percentile") or 0.0) >= 0.9:
            return "epss_high_percentile_context"
    except (TypeError, ValueError):
        pass
    if str(metadata_value(metadata, "cvss_severity") or "").upper() in {"HIGH", "CRITICAL"}:
        return "high_severity_vulnerability_context"
    if metadata_bool_value(metadata, "fixed_version_known"):
        return "patch_prioritization_context"
    return "defensive_exposure_review"


def _rag_citation_id(item: dict[str, Any]) -> str:
    for candidate in (item.get("citation_id"), item.get("chunk_id"), item.get("id")):
        value = str(candidate or "").strip()
        if not value:
            continue
        if not value.startswith("rag:"):
            value = f"rag:{value}"
        if value.lower() not in {"rag:none", "rag:null", "rag:unknown"}:
            return value
    return ""


def _diagnostic_citation_id(item: dict[str, Any]) -> str | None:
    return _rag_citation_id(item) or None


def _safe_output_modes(metadata: dict[str, Any]) -> list[str]:
    output_mode = metadata_list_value(metadata, "output_mode")
    if not output_mode:
        value = metadata_value(metadata, "output_mode")
        output_mode = [value] if isinstance(value, str) else []
    safe_modes: list[str] = []
    for value in output_mode:
        mode = str(value or "").strip()
        if not mode or mode in BLOCKED_VULN_OUTPUT_MODES or mode in safe_modes:
            continue
        safe_modes.append(mode)
    return safe_modes


def _blocked_output_modes(metadata: dict[str, Any]) -> set[str]:
    blocked = metadata_list_value(metadata, "blocked_output_modes")
    if not blocked:
        value = metadata_value(metadata, "blocked_output_modes")
        blocked = [value] if isinstance(value, str) else []
    return {str(value or "").strip() for value in blocked if str(value or "").strip()}


def _summary(metadata: dict[str, Any]) -> str:
    pieces = []
    cve_id = metadata_value(metadata, "cve_id")
    cvss_severity = metadata_value(metadata, "cvss_severity")
    epss_percentile = metadata_value(metadata, "epss_percentile")
    if cve_id:
        pieces.append(str(cve_id))
    if cvss_severity:
        pieces.append(f"severity={cvss_severity}")
    if metadata_bool_value(metadata, "kev"):
        pieces.append("KEV=true")
    if epss_percentile is not None:
        pieces.append(f"EPSS percentile={epss_percentile}")
    if metadata_bool_value(metadata, "fixed_version_known"):
        pieces.append("fix available")
    return "; ".join(pieces) or "Vulnerability intelligence context is available for defensive review."
