from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from primordial_preprocess.filetypes import attack_domain_from_filename, is_attack_json_filename


def classify_sources(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{**record, **classify_record(record)} for record in records]


def classify_record(record: dict[str, Any]) -> dict[str, Any]:
    name = str(record.get("filename") or "").lower()
    rel = str(record.get("relative_path") or "").lower()
    text = f"{name} {rel}"
    text_key = text.replace("_", "-").replace(" ", "-")
    base = {
        "authority_level": "unknown",
        "corpus_type": ["low_signal"],
        "domain": [],
        "planner_visibility": "disabled",
        "risk_level": "unknown",
        "scope_gate_required": False,
        "requires_operator_approval": False,
        "allowed_contexts": ["owned_lab", "ctf", "authorized_security_research"],
        "classification_reason": "default unknown classification",
    }
    if "temporarily unavailable" in text or "researchgate" in text and name.endswith((".html", ".htm")):
        return {
            **base,
            "authority_level": "junk",
            "corpus_type": ["junk"],
            "planner_visibility": "disabled",
            "risk_level": "unknown",
            "quarantine_reason": "junk temporary/unavailable HTML page",
            "classification_reason": "temporary unavailable HTML",
        }
    if is_attack_json_filename(name):
        domain = attack_domain_from_filename(name) or "attack"
        return {
            **base,
            "authority_level": "official_taxonomy",
            "corpus_type": ["attack_taxonomy"],
            "domain": [domain],
            "planner_visibility": "taxonomy_only",
            "risk_level": "safe_planning",
            "scope_gate_required": True,
            "classification_reason": "MITRE ATT&CK STIX JSON",
        }
    if "asvs" in text or "application-security-verification-standard" in text_key:
        return {
            **base,
            "authority_level": "official_standard",
            "corpus_type": ["web_security"],
            "planner_visibility": "normal",
            "risk_level": "safe_planning",
            "classification_reason": "OWASP ASVS",
        }
    if "wstg" in text or "web-security-testing-guide" in text_key:
        return {
            **base,
            "authority_level": "official_standard",
            "corpus_type": ["web_security"],
            "planner_visibility": "normal",
            "risk_level": "active_testing",
            "scope_gate_required": True,
            "classification_reason": "OWASP WSTG",
        }
    if name.endswith(".md") and (name.startswith("0x") or "api-security" in text or "owasp" in text):
        return {
            **base,
            "authority_level": "official_standard",
            "corpus_type": ["api_security"],
            "planner_visibility": "normal",
            "risk_level": "safe_planning",
            "classification_reason": "OWASP API Security Top 10",
        }
    if "sp800" in text or "800-115" in text or "nist" in text:
        return {
            **base,
            "authority_level": "official_governance",
            "corpus_type": ["engagement_governance"],
            "planner_visibility": "normal",
            "risk_level": "safe_planning",
            "classification_reason": "NIST engagement guidance",
        }
    if "ptes" in text:
        return {
            **base,
            "authority_level": "official_governance",
            "corpus_type": ["engagement_governance"],
            "planner_visibility": "normal",
            "risk_level": "active_testing",
            "scope_gate_required": True,
            "classification_reason": "PTES methodology",
        }
    if "kubernetes" in text:
        restricted = "hacking" in text
        return {
            **base,
            "authority_level": "advanced_practical" if restricted else "vendor_primary",
            "corpus_type": ["kubernetes_security", "cloud_native_security"],
            "planner_visibility": "restricted" if restricted else "normal",
            "risk_level": "active_testing" if restricted else "safe_planning",
            "scope_gate_required": restricted,
            "requires_operator_approval": restricted,
            "classification_reason": "Kubernetes security material",
        }
    if "container-security" in text_key:
        return {
            **base,
            "authority_level": "explanatory_practical",
            "corpus_type": ["container_security", "cloud_native_security"],
            "planner_visibility": "normal",
            "risk_level": "safe_planning",
            "classification_reason": "container security reference",
        }
    if "decision-procedures" in text_key:
        return {
            **base,
            "authority_level": "research_foundation",
            "corpus_type": ["decision_procedures", "formal_methods"],
            "planner_visibility": "normal",
            "risk_level": "safe_planning",
            "classification_reason": "formal methods foundation",
        }
    if "string-analysis" in text_key:
        return {
            **base,
            "authority_level": "research_foundation",
            "corpus_type": ["string_analysis", "formal_methods", "web_security"],
            "planner_visibility": "normal",
            "risk_level": "safe_planning",
            "classification_reason": "string analysis foundation",
        }
    if "tamarin" in text:
        return {
            **base,
            "authority_level": "research_practical_bridge",
            "corpus_type": ["protocol_verification", "formal_methods"],
            "planner_visibility": "normal",
            "risk_level": "safe_planning",
            "classification_reason": "Tamarin protocol verification",
        }
    if "hardware-security" in text_key:
        return {
            **base,
            "authority_level": "research_foundation",
            "corpus_type": ["hardware_security"],
            "planner_visibility": "restricted",
            "risk_level": "safe_planning",
            "classification_reason": "hardware security reference",
        }
    if "binary-analysis" in text_key:
        return _restricted(base, ["binary_analysis"], "Practical binary analysis")
    if "kernel-exploitation" in text_key or "linux-kernel" in text_key:
        return _restricted(base, ["kernel_security"], "kernel exploitation/security material")
    if "metasploit" in text:
        return _quarantine_tool(base, "Metasploit tool reference")
    if "powershell" in text:
        return _quarantine_tool(base, "PowerShell automation/tooling")
    if "pfsense" in text:
        return {
            **base,
            "authority_level": "tool_reference",
            "corpus_type": ["firewall_admin"],
            "planner_visibility": "quarantine",
            "risk_level": "unknown",
            "requires_operator_approval": True,
            "quarantine_reason": "firewall admin material disabled unless explicitly enabled",
            "classification_reason": "pfSense admin reference",
        }
    if "web-application-hackers-handbook" in text or "web application hacker" in text:
        return {
            **base,
            "authority_level": "legacy_reference",
            "corpus_type": ["web_security"],
            "planner_visibility": "normal",
            "risk_level": "active_testing",
            "scope_gate_required": True,
            "classification_reason": "legacy web security reference",
        }
    if "web-application-security" in text:
        return {
            **base,
            "authority_level": "explanatory_practical",
            "corpus_type": ["web_security", "api_security"],
            "planner_visibility": "normal",
            "risk_level": "safe_planning",
            "classification_reason": "web application security reference",
        }
    if "api-security-in-action" in text_key:
        return {
            **base,
            "authority_level": "explanatory_practical",
            "corpus_type": ["api_security"],
            "planner_visibility": "normal",
            "risk_level": "safe_planning",
            "classification_reason": "API security reference",
        }
    if "network-security-assessment" in text_key:
        return {
            **base,
            "authority_level": "explanatory_practical",
            "corpus_type": ["network_security"],
            "planner_visibility": "normal",
            "risk_level": "passive_recon",
            "scope_gate_required": True,
            "classification_reason": "network security assessment reference",
        }
    if "hacking" in text or "exploitation" in text:
        return {
            **base,
            "authority_level": "low_authority",
            "corpus_type": ["low_signal"],
            "planner_visibility": "quarantine",
            "risk_level": "unknown",
            "requires_operator_approval": True,
            "quarantine_reason": "generic hacking/exploitation title requires review",
            "classification_reason": "generic hacking/exploitation title",
        }
    return base


def write_classification_outputs(records: list[dict[str, Any]], output_dir: Path | str) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "classified_sources.jsonl").open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True))
            handle.write("\n")
    authority = Counter(str(record["authority_level"]) for record in records)
    corpus = Counter(
        item
        for record in records
        for item in record.get("corpus_type", [])
    )
    lines = [
        "# Classification Report",
        "",
        f"Total sources: {len(records)}",
        "",
        "## Authority Levels",
        *[f"- {key}: {value}" for key, value in sorted(authority.items())],
        "",
        "## Corpus Types",
        *[f"- {key}: {value}" for key, value in sorted(corpus.items())],
        "",
        "## Quarantined Or Disabled",
    ]
    for record in records:
        if record.get("planner_visibility") in {"quarantine", "disabled"}:
            lines.append(f"- {record['relative_path']}: {record.get('quarantine_reason') or record.get('classification_reason')}")
    (out / "classification_report.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _restricted(base: dict[str, Any], corpus_type: list[str], reason: str) -> dict[str, Any]:
    return {
        **base,
        "authority_level": "advanced_practical",
        "corpus_type": corpus_type,
        "planner_visibility": "restricted",
        "risk_level": "exploit_validation",
        "scope_gate_required": True,
        "requires_operator_approval": True,
        "classification_reason": reason,
    }


def _quarantine_tool(base: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        **base,
        "authority_level": "tool_reference",
        "corpus_type": ["tool_usage"],
        "planner_visibility": "quarantine",
        "risk_level": "post_exploitation_sensitive",
        "scope_gate_required": True,
        "requires_operator_approval": True,
        "quarantine_reason": reason,
        "classification_reason": reason,
    }
