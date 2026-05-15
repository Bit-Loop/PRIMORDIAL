from __future__ import annotations

from pathlib import Path


TYPE_BY_EXTENSION = {
    ".pdf": "pdf",
    ".epub": "epub",
    ".md": "markdown",
    ".markdown": "markdown",
    ".html": "html",
    ".htm": "html",
    ".json": "json",
    ".txt": "text",
    ".text": "text",
    ".csv": "text",
    ".log": "text",
    ".yaml": "text",
    ".yml": "text",
}


def detect_type(path: Path) -> str:
    return TYPE_BY_EXTENSION.get(path.suffix.lower(), "unknown")


def is_attack_json_filename(filename: str) -> bool:
    normalized = filename.lower()
    return normalized in {
        "enterprise-attack.json",
        "mitre-enterprise-attack.json",
        "mobile-attack.json",
        "mitre-mobile-attack.json",
        "ics-attack.json",
        "mitre-ics-attack.json",
    }


def attack_domain_from_filename(filename: str) -> str | None:
    normalized = filename.lower()
    if "enterprise" in normalized and normalized.endswith("attack.json"):
        return "enterprise"
    if "mobile" in normalized and normalized.endswith("attack.json"):
        return "mobile"
    if "ics" in normalized and normalized.endswith("attack.json"):
        return "ics"
    return None
