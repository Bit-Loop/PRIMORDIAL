from __future__ import annotations

import re
from typing import Iterable, Mapping


RAG_LEGACY_CORPUS_TYPES = frozenset({"operator_note", "cve_advisory", "exploit_note", "htb_writeup"})
RAG_CORPUS_TYPES = frozenset(
    {
        *RAG_LEGACY_CORPUS_TYPES,
        "api_security",
        "web_security",
        "kubernetes_cloud",
        "container_security",
        "network_infra",
        "windows_linux",
        "powershell_ops",
        "methodology_standards",
        "mitre_attack",
        "binary_exploitation",
        "kernel_security",
        "hardware_security",
        "formal_methods",
        "platform_metadata",
        "vuln_intel",
        "package_security",
        "cloud_security",
        "ctf_trajectory",
        "general_security",
    }
)
RAG_CORPUS_ALIASES = {
    "api_web": "api_security",
    "attack_taxonomy": "mitre_attack",
    "binary_analysis": "binary_exploitation",
    "cloud_native_security": "kubernetes_cloud",
    "engagement_governance": "methodology_standards",
    "firewall_admin": "network_infra",
    "kubernetes_security": "kubernetes_cloud",
    "network_security": "network_infra",
    "program_analysis": "formal_methods",
    "protocol_verification": "formal_methods",
    "string_analysis": "formal_methods",
    "systems_exploitation": "binary_exploitation",
    "tool_usage": "powershell_ops",
    "vulnerability_intel": "vuln_intel",
    "vulnerability": "vuln_intel",
    "vuln": "vuln_intel",
}


def normalized_context_key(value: object) -> str:
    text = "" if value is None else str(value)
    return re.sub(r"[^a-z0-9]+", "_", text.strip().lower()).strip("_")


def normalized_context_keys(values: Iterable[object]) -> set[str]:
    return {key for value in values if (key := normalized_context_key(value))}


def canonical_rag_domain(
    value: object,
    *,
    blank: str = "general_security",
    unknown: str = "general_security",
) -> str:
    normalized = normalized_context_key(value)
    if not normalized:
        normalized = normalized_context_key(blank)
    canonical = RAG_CORPUS_ALIASES.get(normalized, normalized)
    if canonical in RAG_CORPUS_TYPES:
        return canonical
    return unknown


def normalized_metadata_value(metadata: Mapping[str, object], *names: object) -> str:
    normalized_names = normalized_context_keys(names)
    for raw_key, value in metadata.items():
        if normalized_context_key(raw_key) in normalized_names:
            return normalized_context_key(value)
    return ""


def metadata_value(metadata: Mapping[str, object], *names: object) -> object | None:
    normalized_names = normalized_context_keys(names)
    for raw_key, value in metadata.items():
        if normalized_context_key(raw_key) in normalized_names:
            return value
    return None


def metadata_list_value(metadata: Mapping[str, object], *names: object) -> list[object]:
    value = metadata_value(metadata, *names)
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    return []


def metadata_bool_value(metadata: Mapping[str, object], *names: object) -> bool:
    value = metadata_value(metadata, *names)
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
