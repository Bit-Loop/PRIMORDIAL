from __future__ import annotations

from typing import Any

from .osv import event_for_osv, parse_osv


def parse_ghsa(payload: dict[str, Any], *, raw_ref: str = ""):
    if "id" in payload and str(payload.get("id", "")).upper().startswith("GHSA-"):
        return parse_osv(payload, raw_ref=raw_ref, source_name="ghsa")
    aliases = payload.get("aliases") if isinstance(payload.get("aliases"), list) else []
    ghsa_id = str(payload.get("ghsa_id") or payload.get("id") or "").upper()
    osv_payload = {
        "id": ghsa_id,
        "aliases": aliases,
        "summary": payload.get("summary") or payload.get("description") or "",
        "details": payload.get("description") or payload.get("details") or "",
        "modified": payload.get("updated_at") or payload.get("modified") or "",
        "published": payload.get("published_at") or payload.get("published") or "",
        "affected": _affected(payload),
        "references": [{"type": "WEB", "url": url} for url in payload.get("references", []) if isinstance(url, str)],
        "severity": payload.get("severity", []),
    }
    return parse_osv(osv_payload, raw_ref=raw_ref, source_name="ghsa")


def event_for_ghsa(payload: dict[str, Any], *, raw_ref: str = ""):
    return event_for_osv(payload, raw_ref=raw_ref, source_name="ghsa")


def _affected(payload: dict[str, Any]) -> list[dict[str, Any]]:
    vulnerabilities = payload.get("vulnerabilities") if isinstance(payload.get("vulnerabilities"), list) else []
    out: list[dict[str, Any]] = []
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        package = item.get("package") if isinstance(item.get("package"), dict) else {}
        patched = item.get("first_patched_version")
        if isinstance(patched, dict):
            patched_version = str(patched.get("identifier") or patched.get("version") or "")
        else:
            patched_version = str(patched or "")
        out.append(
            {
                "package": {
                    "ecosystem": package.get("ecosystem") or item.get("ecosystem", ""),
                    "name": package.get("name") or item.get("package_name", ""),
                },
                "ranges": [{"type": item.get("vulnerable_version_range") or "", "events": [{"fixed": patched_version}]}],
            }
        )
    return out
