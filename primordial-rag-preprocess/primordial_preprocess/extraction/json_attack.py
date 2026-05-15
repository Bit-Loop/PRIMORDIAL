from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from primordial_preprocess.filetypes import attack_domain_from_filename
from primordial_preprocess.hashing import sha256_file, stable_id


def parse_attack_file(path: Path | str) -> list[dict[str, Any]]:
    source_path = Path(path)
    payload = json.loads(source_path.read_text(encoding="utf-8"))
    objects = payload.get("objects", [])
    if not isinstance(objects, list):
        raise ValueError(f"ATT&CK JSON objects must be a list: {source_path}")
    by_ref = {str(obj.get("id")): obj for obj in objects if isinstance(obj, dict) and obj.get("id")}
    relationships = [obj for obj in objects if isinstance(obj, dict) and obj.get("type") == "relationship"]
    source_sha256 = sha256_file(source_path)
    domain = attack_domain_from_filename(source_path.name) or "attack"
    records: list[dict[str, Any]] = []
    for obj in objects:
        if not isinstance(obj, dict) or not obj.get("id"):
            continue
        records.append(_record_for_object(obj, source_sha256, domain, relationships, by_ref))
    records.sort(key=lambda item: (str(item["object_type"]), str(item.get("technique_id") or ""), str(item.get("name") or "")))
    return records


def write_attack_outputs(records_by_domain: dict[str, list[dict[str, Any]]], output_dir: Path | str) -> None:
    out = Path(output_dir) / "attack"
    out.mkdir(parents=True, exist_ok=True)
    for domain, records in sorted(records_by_domain.items()):
        path = out / f"{domain}_records.jsonl"
        with path.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, sort_keys=True))
                handle.write("\n")


def _external_id(obj: dict[str, Any]) -> str:
    refs = obj.get("external_references", [])
    if not isinstance(refs, list):
        return ""
    for ref in refs:
        if isinstance(ref, dict) and str(ref.get("source_name") or "").lower() == "mitre-attack":
            return str(ref.get("external_id") or "")
    return ""


def _record_for_object(
    obj: dict[str, Any],
    source_sha256: str,
    domain: str,
    relationships: list[dict[str, Any]],
    by_ref: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    stix_id = str(obj.get("id") or "")
    object_type = str(obj.get("type") or "")
    technique_id = _external_id(obj) if object_type == "attack-pattern" else ""
    tactics = [
        str(item.get("phase_name"))
        for item in obj.get("kill_chain_phases", [])
        if isinstance(item, dict) and item.get("phase_name")
    ]
    return {
        "record_id": stable_id("attck", source_sha256, stix_id, length=20),
        "attack_domain": domain,
        "object_type": object_type,
        "technique_id": technique_id,
        "stix_id": stix_id,
        "name": str(obj.get("name") or obj.get("relationship_type") or ""),
        "description": str(obj.get("description") or ""),
        "tactics": tactics,
        "platforms": _string_list(obj.get("x_mitre_platforms")),
        "data_sources": _data_sources_for(stix_id, obj, relationships, by_ref),
        "detection": str(obj.get("x_mitre_detection") or ""),
        "mitigations": _mitigations_for(stix_id, relationships, by_ref) if object_type == "attack-pattern" else [],
        "relationships": _relationships_for(stix_id, relationships, by_ref),
        "revoked": bool(obj.get("revoked")),
        "deprecated": bool(obj.get("x_mitre_deprecated")),
        "external_references": obj.get("external_references", []),
        "source_modified": str(obj.get("modified") or ""),
        "x_mitre_version": str(obj.get("x_mitre_version") or ""),
        "source_sha256": source_sha256,
        "source_object": obj,
    }


def _string_list(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _relationships_for(stix_id: str, relationships: list[dict[str, Any]], by_ref: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    related: list[dict[str, Any]] = []
    for rel in relationships:
        if rel.get("source_ref") != stix_id and rel.get("target_ref") != stix_id:
            continue
        source = by_ref.get(str(rel.get("source_ref") or ""), {})
        target = by_ref.get(str(rel.get("target_ref") or ""), {})
        related.append(
            {
                "relationship_type": rel.get("relationship_type"),
                "source_ref": rel.get("source_ref"),
                "source_id": _external_id(source),
                "source_name": source.get("name", ""),
                "target_ref": rel.get("target_ref"),
                "target_id": _external_id(target),
                "target_name": target.get("name", ""),
                "description": rel.get("description", ""),
                "source_relationship": rel,
            }
        )
    return related


def _mitigations_for(stix_id: str, relationships: list[dict[str, Any]], by_ref: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    mitigations: list[dict[str, Any]] = []
    for rel in relationships:
        if rel.get("relationship_type") != "mitigates" or rel.get("target_ref") != stix_id:
            continue
        mitigation = by_ref.get(str(rel.get("source_ref") or ""), {})
        if mitigation.get("type") == "course-of-action":
            mitigations.append(
                {
                    "mitigation_id": _external_id(mitigation),
                    "name": mitigation.get("name", ""),
                    "description": mitigation.get("description", ""),
                    "source_object": mitigation,
                }
            )
    return mitigations


def _data_sources_for(
    stix_id: str,
    technique: dict[str, Any],
    relationships: list[dict[str, Any]],
    by_ref: dict[str, dict[str, Any]],
) -> list[str]:
    names = set(_string_list(technique.get("x_mitre_data_sources")))
    for rel in relationships:
        if rel.get("relationship_type") != "detects" or rel.get("target_ref") != stix_id:
            continue
        detector = by_ref.get(str(rel.get("source_ref") or ""), {})
        if detector.get("type") == "x-mitre-data-component" and detector.get("name"):
            names.add(str(detector["name"]))
        for analytic_ref in _string_list(detector.get("x_mitre_analytic_refs")):
            analytic = by_ref.get(analytic_ref, {})
            for log_source in analytic.get("x_mitre_log_source_references", []) or []:
                if not isinstance(log_source, dict):
                    continue
                component = by_ref.get(str(log_source.get("x_mitre_data_component_ref") or ""), {})
                if component.get("name"):
                    names.add(str(component["name"]))
    return sorted(names)
