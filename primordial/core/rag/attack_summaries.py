from __future__ import annotations

from typing import Any


class AttackSummaryMixin:
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
        attack_patterns_with_external_id = [
            str(obj.get("id")) for obj in attack_patterns if self._external_id(obj)
        ]
        technique_stix_ids = {str(record.get("stix_id")) for record in records}
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
