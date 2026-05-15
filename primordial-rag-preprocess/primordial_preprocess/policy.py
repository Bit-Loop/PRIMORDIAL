from __future__ import annotations

from typing import Any

from primordial_preprocess.config import CorpusPolicy, SourceOverride
from primordial_preprocess.filetypes import is_attack_json_filename


def apply_policy(
    records: list[dict[str, Any]],
    policy: CorpusPolicy,
    overrides: dict[str, SourceOverride] | None = None,
) -> list[dict[str, Any]]:
    overrides = overrides or {}
    return [apply_policy_to_record(record, policy, overrides.get(str(record.get("sha256")))) for record in records]


def apply_policy_to_record(
    record: dict[str, Any],
    policy: CorpusPolicy,
    override: SourceOverride | None = None,
) -> dict[str, Any]:
    out = dict(record)
    license_status = str(out.get("license_status") or "unknown")
    if policy.allow_operator_overrides and override is not None:
        if override.license_status:
            license_status = override.license_status
        out["operator_override_notes"] = override.notes
    out["license_status"] = license_status
    reason = _policy_block_reason(out, policy, override)
    out["policy_blocked"] = bool(reason)
    out["policy_block_reason"] = reason
    out["extraction_allowed"] = not reason
    return out


def _policy_block_reason(record: dict[str, Any], policy: CorpusPolicy, override: SourceOverride | None) -> str:
    if policy.allow_operator_overrides and override is not None and override.extraction_allowed is True:
        return ""
    if not bool(record.get("recommended_keep", True)) and not policy.allow_duplicate_extraction:
        return "exact duplicate extraction disabled; canonical copy recommended"
    visibility = str(record.get("planner_visibility") or "")
    detected_type = str(record.get("detected_type") or "")
    filename = str(record.get("filename") or "")
    license_status = str(record.get("license_status") or "")
    if visibility in {"disabled", "quarantine"}:
        return f"planner_visibility={visibility}"
    if is_attack_json_filename(filename):
        return "" if policy.extract_attack_json else "ATT&CK JSON extraction disabled by policy"
    if visibility == "restricted" and not policy.extract_restricted_security_books:
        return "restricted security material extraction disabled by policy"
    if "unknown_commercial_or_proprietary" in license_status and not policy.extract_commercial_unknown_license:
        return "unknown commercial/proprietary license requires explicit operator override"
    if detected_type == "markdown":
        return "" if policy.extract_markdown else "markdown extraction disabled by policy"
    if detected_type == "html" and not (policy.extract_html or policy.extract_known_docs_html):
        return "HTML extraction disabled by policy"
    return ""


def docling_required_reason() -> str:
    return "Docling is required; no fallback extractors are enabled"
