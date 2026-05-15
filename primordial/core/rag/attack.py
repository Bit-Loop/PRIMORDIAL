from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from primordial.core.domain.models import utc_now


ATTCK_ALLOWED_USES = [
    "behavior_classification",
    "evidence_mapping",
    "reporting_vocabulary",
    "detection_mitigation_alignment",
]

ATTCK_PROHIBITED_USES = [
    "scope_decision",
    "aggressive_action_selection",
    "authorization_bypass",
    "post_exploitation_planning_outside_authorized_lab",
]


@dataclass(frozen=True, slots=True)
class AttackIndexSpec:
    domain: str
    index_name: str
    source_candidates: tuple[str, ...]


class AttackPreprocessError(RuntimeError):
    pass


class AttackIndexPreprocessor:
    INDEX_SPECS = (
        AttackIndexSpec(
            domain="enterprise-attack",
            index_name="attck_enterprise_index",
            source_candidates=("enterprise-attack.json", "mitre-enterprise-attack.json"),
        ),
        AttackIndexSpec(
            domain="mobile-attack",
            index_name="attck_mobile_index",
            source_candidates=("mobile-attack.json", "mitre-mobile-attack.json"),
        ),
        AttackIndexSpec(
            domain="ics-attack",
            index_name="attck_ics_index",
            source_candidates=("ics-attack.json", "mitre-ics-attack.json"),
        ),
    )

    def preprocess(self, *, source_dir: Path | str, output_root: Path | str) -> dict[str, object]:
        source_root = Path(source_dir).expanduser().resolve()
        output_root = Path(output_root).expanduser().resolve()
        if not source_root.exists() or not source_root.is_dir():
            raise AttackPreprocessError(f"ATT&CK source directory does not exist: {source_root}")
        output_root.mkdir(parents=True, exist_ok=True)
        indexes = [
            self.build_index(source_path=self._resolve_source(source_root, spec), spec=spec, output_root=output_root)
            for spec in self.INDEX_SPECS
        ]
        catalog = {
            "generated_at": utc_now().isoformat(),
            "index_mode": "structured_attck_records",
            "raw_vectorized": False,
            "structured_records_vectorized": False,
            "allowed_uses": ATTCK_ALLOWED_USES,
            "prohibited_uses": ATTCK_PROHIBITED_USES,
            "indexes": indexes,
        }
        self._write_json(output_root / "attck_index_catalog.json", catalog)
        return catalog

    def build_index(self, *, source_path: Path, spec: AttackIndexSpec, output_root: Path) -> dict[str, object]:
        payload = self._read_json(source_path)
        objects = payload.get("objects", [])
        if not isinstance(objects, list):
            raise AttackPreprocessError(f"ATT&CK bundle objects must be a list: {source_path}")
        if not all(isinstance(obj, dict) for obj in objects):
            raise AttackPreprocessError(f"ATT&CK bundle contains non-object entries: {source_path}")
        source_sha256 = self._sha256(source_path)
        source_objects = [self._source_object_record(obj, source_sha256=source_sha256) for obj in objects]
        object_type_counts = self._object_type_counts(objects)
        by_ref = {str(obj.get("id")): obj for obj in objects if obj.get("id")}
        relationships = [obj for obj in objects if obj.get("type") == "relationship"]
        attack_patterns = [obj for obj in objects if obj.get("type") == "attack-pattern"]
        records = [
            self._technique_record(
                technique=obj,
                domain=spec.domain,
                by_ref=by_ref,
                relationships=relationships,
                source_sha256=source_sha256,
            )
            for obj in attack_patterns
        ]
        records = [record for record in records if record is not None]
        records.sort(key=lambda record: str(record["technique_id"]))
        completeness = self._completeness_report(objects=objects, source_objects=source_objects, records=records)
        index_dir = output_root / spec.index_name
        index_dir.mkdir(parents=True, exist_ok=True)
        by_technique_id = {str(record["technique_id"]): record for record in records}
        relationships_flat = [
            {"technique_id": record["technique_id"], **relationship}
            for record in records
            for relationship in record["relationships"]
        ]
        indexes = {
            "by_technique_id": sorted(by_technique_id),
            "by_tactic": self._group_by_list_field(records, "tactic"),
            "by_platform": self._group_by_list_field(records, "platforms"),
            "by_data_source": self._group_by_list_field(records, "data_sources"),
        }
        manifest = {
            "generated_at": utc_now().isoformat(),
            "index_name": spec.index_name,
            "domain": spec.domain,
            "source_path": str(source_path),
            "source_sha256": source_sha256,
            "bundle_type": payload.get("type"),
            "bundle_id": payload.get("id"),
            "spec_version": payload.get("spec_version"),
            "stix_object_count": len(objects),
            "preserved_stix_object_count": len(source_objects),
            "object_type_counts": object_type_counts,
            "technique_count": len(records),
            "relationship_count": len(relationships_flat),
            "revoked_count": sum(1 for record in records if record["revoked"]),
            "deprecated_count": sum(1 for record in records if record["deprecated"]),
            "index_mode": "structured_attck_records",
            "raw_vectorized": False,
            "structured_records_vectorized": False,
            "lossless_source_objects": True,
            "completeness": completeness,
            "allowed_uses": ATTCK_ALLOWED_USES,
            "prohibited_uses": ATTCK_PROHIBITED_USES,
            "files": {
                "records_jsonl": "records.jsonl",
                "records_json": "records.json",
                "stix_objects_jsonl": "stix_objects.jsonl",
                "stix_object_locator": "stix_object_locator.json",
                "completeness_report": "completeness_report.json",
                "by_technique_id": "by_technique_id.json",
                "by_tactic": "by_tactic.json",
                "by_platform": "by_platform.json",
                "by_data_source": "by_data_source.json",
                "relationships_jsonl": "relationships.jsonl",
            },
        }
        self._write_json(index_dir / "manifest.json", manifest)
        self._write_jsonl(index_dir / "records.jsonl", records)
        self._write_json(index_dir / "records.json", records)
        self._write_jsonl(index_dir / "stix_objects.jsonl", source_objects)
        self._write_json(index_dir / "stix_object_locator.json", self._stix_object_locator(source_objects))
        self._write_json(index_dir / "completeness_report.json", completeness)
        self._write_json(index_dir / "by_technique_id.json", by_technique_id)
        self._write_json(index_dir / "by_tactic.json", indexes["by_tactic"])
        self._write_json(index_dir / "by_platform.json", indexes["by_platform"])
        self._write_json(index_dir / "by_data_source.json", indexes["by_data_source"])
        self._write_jsonl(index_dir / "relationships.jsonl", relationships_flat)
        return {
            "index_name": spec.index_name,
            "domain": spec.domain,
            "path": str(index_dir),
            "source_path": str(source_path),
            "source_sha256": source_sha256,
            "stix_object_count": len(objects),
            "preserved_stix_object_count": len(source_objects),
            "technique_count": len(records),
            "relationship_count": len(relationships_flat),
            "lossless_source_objects": True,
            "raw_vectorized": False,
        }

    def _technique_record(
        self,
        *,
        technique: dict[str, Any],
        domain: str,
        by_ref: dict[str, dict[str, Any]],
        relationships: list[dict[str, Any]],
        source_sha256: str,
    ) -> dict[str, Any] | None:
        technique_id = self._external_id(technique)
        if not technique_id:
            return None
        tactics = [
            str(item.get("phase_name"))
            for item in technique.get("kill_chain_phases", [])
            if isinstance(item, dict) and item.get("phase_name")
        ]
        technique_ref = str(technique.get("id"))
        related = self._relationships_for(technique_ref, relationships=relationships, by_ref=by_ref)
        data_sources, data_components = self._data_sources_for_technique(
            technique,
            technique_ref=technique_ref,
            relationships=relationships,
            by_ref=by_ref,
        )
        mitigations = [
            self._mitigation_record(rel, by_ref)
            for rel in relationships
            if rel.get("relationship_type") == "mitigates" and rel.get("target_ref") == technique_ref
        ]
        mitigations = [item for item in mitigations if item is not None]
        source_date = str(technique.get("modified") or technique.get("created") or "")
        domains = technique.get("x_mitre_domains", [])
        selected_domain = str(domains[0]) if isinstance(domains, list) and domains else domain
        return {
            "technique_id": technique_id,
            "stix_id": technique_ref,
            "name": str(technique.get("name") or ""),
            "domain": selected_domain,
            "tactic": tactics,
            "description": str(technique.get("description") or ""),
            "platforms": self._string_list(technique.get("x_mitre_platforms")),
            "data_sources": data_sources,
            "data_components": data_components,
            "detection": str(technique.get("x_mitre_detection") or ""),
            "mitigations": mitigations,
            "relationships": related,
            "revoked": bool(technique.get("revoked")),
            "deprecated": bool(technique.get("x_mitre_deprecated")),
            "version": str(technique.get("x_mitre_version") or ""),
            "source_date": source_date,
            "created": str(technique.get("created") or ""),
            "modified": str(technique.get("modified") or ""),
            "attack_spec_version": str(technique.get("x_mitre_attack_spec_version") or ""),
            "source_sha256": source_sha256,
            "source_object_sha256": self._object_sha256(technique),
            "source_object": technique,
            "usage_policy": {
                "allowed_uses": ATTCK_ALLOWED_USES,
                "prohibited_uses": ATTCK_PROHIBITED_USES,
            },
        }

    def _data_sources_for_technique(
        self,
        technique: dict[str, Any],
        *,
        technique_ref: str,
        relationships: list[dict[str, Any]],
        by_ref: dict[str, dict[str, Any]],
    ) -> tuple[list[str], list[dict[str, object]]]:
        names = set(self._string_list(technique.get("x_mitre_data_sources")))
        components: list[dict[str, object]] = []
        seen_components: set[tuple[str, str, str, str]] = set()
        for rel in relationships:
            if rel.get("relationship_type") != "detects" or rel.get("target_ref") != technique_ref:
                continue
            detector_ref = str(rel.get("source_ref") or "")
            detector = by_ref.get(detector_ref, {})
            detector_type = str(detector.get("type") or "")
            if detector_type == "x-mitre-data-component":
                self._add_data_component(
                    components,
                    names,
                    seen_components,
                    component=detector,
                    log_source={},
                    analytic={},
                    detection_strategy={},
                )
                continue
            if detector_type != "x-mitre-detection-strategy":
                continue
            for analytic_ref in self._string_list(detector.get("x_mitre_analytic_refs")):
                analytic = by_ref.get(analytic_ref, {})
                log_sources = analytic.get("x_mitre_log_source_references", [])
                if not isinstance(log_sources, list):
                    continue
                for log_source in log_sources:
                    if not isinstance(log_source, dict):
                        continue
                    component_ref = str(log_source.get("x_mitre_data_component_ref") or "")
                    component = by_ref.get(component_ref, {})
                    self._add_data_component(
                        components,
                        names,
                        seen_components,
                        component=component,
                        log_source=log_source,
                        analytic=analytic,
                        detection_strategy=detector,
                    )
        return sorted(names), sorted(components, key=lambda item: (str(item["name"]), str(item["log_source"])))

    def _add_data_component(
        self,
        components: list[dict[str, object]],
        names: set[str],
        seen: set[tuple[str, str, str, str]],
        *,
        component: dict[str, Any],
        log_source: dict[str, Any],
        analytic: dict[str, Any],
        detection_strategy: dict[str, Any],
    ) -> None:
        component_name = str(component.get("name") or "").strip()
        log_name = str(log_source.get("name") or "").strip()
        channel = str(log_source.get("channel") or "").strip()
        if component_name:
            names.add(component_name)
        elif log_name:
            names.add(log_name)
        key = (
            str(component.get("id") or ""),
            component_name,
            log_name,
            channel,
        )
        if key in seen:
            return
        seen.add(key)
        components.append(
            {
                "component_id": self._external_id(component),
                "stix_id": str(component.get("id") or ""),
                "name": component_name or log_name,
                "description": str(component.get("description") or ""),
                "log_source": log_name,
                "channel": channel,
                "analytic_id": self._external_id(analytic),
                "analytic_name": str(analytic.get("name") or ""),
                "detection_strategy_id": self._external_id(detection_strategy),
                "detection_strategy_name": str(detection_strategy.get("name") or ""),
            }
        )

    def _relationships_for(
        self,
        technique_ref: str,
        *,
        relationships: list[dict[str, Any]],
        by_ref: dict[str, dict[str, Any]],
    ) -> list[dict[str, object]]:
        items: list[dict[str, object]] = []
        for rel in relationships:
            source_ref = str(rel.get("source_ref") or "")
            target_ref = str(rel.get("target_ref") or "")
            if source_ref != technique_ref and target_ref != technique_ref:
                continue
            other_ref = target_ref if source_ref == technique_ref else source_ref
            other = by_ref.get(other_ref, {})
            items.append(
                {
                    "relationship_id": str(rel.get("id") or ""),
                    "relationship_type": str(rel.get("relationship_type") or ""),
                    "direction": "outbound" if source_ref == technique_ref else "inbound",
                    "source_ref": source_ref,
                    "source_id": self._external_id(by_ref.get(source_ref, {})),
                    "source_name": str(by_ref.get(source_ref, {}).get("name") or ""),
                    "target_ref": target_ref,
                    "target_id": self._external_id(by_ref.get(target_ref, {})),
                    "target_name": str(by_ref.get(target_ref, {}).get("name") or ""),
                    "other_ref": other_ref,
                    "other_type": str(other.get("type") or ""),
                    "other_id": self._external_id(other),
                    "other_name": str(other.get("name") or ""),
                    "description": str(rel.get("description") or ""),
                    "revoked": bool(rel.get("revoked")),
                    "deprecated": bool(rel.get("x_mitre_deprecated")),
                    "source_object_sha256": self._object_sha256(rel),
                    "source_relationship": rel,
                }
            )
        return items

    def _mitigation_record(self, relationship: dict[str, Any], by_ref: dict[str, dict[str, Any]]) -> dict[str, object] | None:
        mitigation = by_ref.get(str(relationship.get("source_ref") or ""), {})
        if mitigation.get("type") != "course-of-action":
            return None
        return {
            "mitigation_id": self._external_id(mitigation),
            "stix_id": str(mitigation.get("id") or ""),
            "name": str(mitigation.get("name") or ""),
            "description": str(mitigation.get("description") or ""),
            "relationship_id": str(relationship.get("id") or ""),
            "source_object_sha256": self._object_sha256(mitigation),
            "source_relationship_sha256": self._object_sha256(relationship),
        }

    def _source_object_record(self, obj: dict[str, Any], *, source_sha256: str) -> dict[str, object]:
        return {
            "stix_id": str(obj.get("id") or ""),
            "type": str(obj.get("type") or ""),
            "external_id": self._external_id(obj),
            "name": str(obj.get("name") or ""),
            "created": str(obj.get("created") or ""),
            "modified": str(obj.get("modified") or ""),
            "revoked": bool(obj.get("revoked")),
            "deprecated": bool(obj.get("x_mitre_deprecated")),
            "source_sha256": source_sha256,
            "source_object_sha256": self._object_sha256(obj),
            "source_object": obj,
        }

    def _object_type_counts(self, objects: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for obj in objects:
            key = str(obj.get("type") or "<missing>")
            counts[key] = counts.get(key, 0) + 1
        return {key: counts[key] for key in sorted(counts)}

    def _stix_object_locator(self, source_objects: list[dict[str, object]]) -> dict[str, dict[str, object]]:
        locator: dict[str, dict[str, object]] = {}
        for index, obj in enumerate(source_objects):
            stix_id = str(obj.get("stix_id") or "")
            if not stix_id:
                continue
            locator[stix_id] = {
                "jsonl_line": index + 1,
                "type": obj.get("type"),
                "external_id": obj.get("external_id"),
                "name": obj.get("name"),
                "source_object_sha256": obj.get("source_object_sha256"),
            }
        return locator

    def _completeness_report(
        self,
        *,
        objects: list[dict[str, Any]],
        source_objects: list[dict[str, object]],
        records: list[dict[str, Any]],
    ) -> dict[str, object]:
        source_ids = {str(obj.get("id")) for obj in objects if obj.get("id")}
        preserved_ids = {str(obj.get("stix_id")) for obj in source_objects if obj.get("stix_id")}
        attack_patterns = [obj for obj in objects if obj.get("type") == "attack-pattern"]
        technique_stix_ids = {str(record.get("stix_id")) for record in records}
        attack_patterns_with_external_id = [
            str(obj.get("id")) for obj in attack_patterns if self._external_id(obj)
        ]
        missing_technique_stix_ids = sorted(set(attack_patterns_with_external_id) - technique_stix_ids)
        missing_source_object_ids = sorted(source_ids - preserved_ids)
        return {
            "source_object_count": len(objects),
            "preserved_source_object_count": len(source_objects),
            "missing_source_object_ids": missing_source_object_ids,
            "source_objects_complete": not missing_source_object_ids,
            "attack_pattern_count": len(attack_patterns),
            "attack_patterns_with_mitre_external_id": len(attack_patterns_with_external_id),
            "technique_record_count": len(records),
            "missing_technique_stix_ids": missing_technique_stix_ids,
            "technique_records_complete": not missing_technique_stix_ids,
            "lossless_source_objects": True,
            "raw_vectorized": False,
        }

    def _resolve_source(self, source_root: Path, spec: AttackIndexSpec) -> Path:
        for name in spec.source_candidates:
            path = source_root / name
            if path.exists() and path.is_file():
                return path
        expected = ", ".join(spec.source_candidates)
        raise AttackPreprocessError(f"missing ATT&CK source for {spec.domain}; expected one of: {expected}")

    def _read_json(self, path: Path) -> dict[str, Any]:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise AttackPreprocessError(f"ATT&CK source must be a JSON object: {path}")
        return payload

    def _external_id(self, obj: dict[str, Any]) -> str:
        refs = obj.get("external_references", [])
        if not isinstance(refs, list):
            return ""
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            external_id = str(ref.get("external_id") or "").strip()
            if external_id and str(ref.get("source_name") or "").lower() == "mitre-attack":
                return external_id
        return ""

    def _string_list(self, value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item) for item in value if str(item).strip()]

    def _group_by_list_field(self, records: list[dict[str, Any]], field: str) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for record in records:
            values = record.get(field, [])
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list):
                continue
            for value in values:
                key = str(value).strip()
                if not key:
                    continue
                grouped.setdefault(key, []).append(str(record["technique_id"]))
        return {key: sorted(set(values)) for key, values in sorted(grouped.items())}

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _object_sha256(self, obj: dict[str, Any]) -> str:
        body = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def _write_json(self, path: Path, payload: object) -> None:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _write_jsonl(self, path: Path, records: list[dict[str, Any]]) -> None:
        with path.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, sort_keys=True))
                handle.write("\n")
