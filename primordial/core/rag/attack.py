from __future__ import annotations

from pathlib import Path
from typing import Any

from primordial.core.domain.models import utc_now
from primordial.core.rag.attack_io import AttackIndexIOMixin
from primordial.core.rag.attack_records import AttackRecordMixin
from primordial.core.rag.attack_summaries import AttackSummaryMixin
from primordial.core.rag.attack_types import (
    ATTCK_ALLOWED_USES,
    ATTCK_PROHIBITED_USES,
    AttackIndexSpec,
    AttackPreprocessError,
)

__all__ = [
    "ATTCK_ALLOWED_USES",
    "ATTCK_PROHIBITED_USES",
    "AttackIndexPreprocessor",
    "AttackIndexSpec",
    "AttackPreprocessError",
]


class AttackIndexPreprocessor(AttackIndexIOMixin, AttackRecordMixin, AttackSummaryMixin):
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
        catalog = self._catalog(indexes)
        self._write_json(output_root / "attck_index_catalog.json", catalog)
        return catalog

    def build_index(self, *, source_path: Path, spec: AttackIndexSpec, output_root: Path) -> dict[str, object]:
        payload, objects, source_sha256 = self._index_source_payload(source_path)
        source_objects = [self._source_object_record(obj, source_sha256=source_sha256) for obj in objects]
        records = self._technique_records(objects, spec=spec, source_sha256=source_sha256)
        relationships_flat = [
            {"technique_id": record["technique_id"], **relationship}
            for record in records
            for relationship in record["relationships"]
        ]
        index_dir = output_root / spec.index_name
        index_dir.mkdir(parents=True, exist_ok=True)
        completeness = self._completeness_report(objects=objects, source_objects=source_objects, records=records)
        self._write_index_files(
            index_dir,
            source_objects=source_objects,
            records=records,
            relationships_flat=relationships_flat,
            completeness=completeness,
            manifest=self._manifest(
                payload,
                objects,
                source_objects,
                source_path,
                spec,
                source_sha256,
                records,
                relationships_flat,
                completeness,
            ),
        )
        return self._index_summary(index_dir, source_path, spec, source_sha256, objects, source_objects, records, relationships_flat)

    def _catalog(self, indexes: list[dict[str, object]]) -> dict[str, object]:
        return {
            "generated_at": utc_now().isoformat(),
            "index_mode": "structured_attck_records",
            "raw_vectorized": False,
            "structured_records_vectorized": False,
            "allowed_uses": ATTCK_ALLOWED_USES,
            "prohibited_uses": ATTCK_PROHIBITED_USES,
            "indexes": indexes,
        }

    def _index_source_payload(self, source_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
        payload = self._read_json(source_path)
        objects = payload.get("objects", [])
        if not isinstance(objects, list):
            raise AttackPreprocessError(f"ATT&CK bundle objects must be a list: {source_path}")
        if not all(isinstance(obj, dict) for obj in objects):
            raise AttackPreprocessError(f"ATT&CK bundle contains non-object entries: {source_path}")
        return payload, objects, self._sha256(source_path)

    def _technique_records(self, objects: list[dict[str, Any]], *, spec: AttackIndexSpec, source_sha256: str) -> list[dict[str, Any]]:
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
        return records

    def _manifest(
        self,
        payload: dict[str, Any],
        objects: list[dict[str, Any]],
        source_objects: list[dict[str, object]],
        source_path: Path,
        spec: AttackIndexSpec,
        source_sha256: str,
        records: list[dict[str, Any]],
        relationships_flat: list[dict[str, object]],
        completeness: dict[str, object],
    ) -> dict[str, object]:
        return {
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
            "object_type_counts": self._object_type_counts(objects),
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
            "files": self._index_file_map(),
        }

    def _index_file_map(self) -> dict[str, str]:
        return {
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
        }

    def _write_index_files(
        self,
        index_dir: Path,
        *,
        source_objects: list[dict[str, object]],
        records: list[dict[str, Any]],
        relationships_flat: list[dict[str, object]],
        completeness: dict[str, object],
        manifest: dict[str, object],
    ) -> None:
        by_technique_id = {str(record["technique_id"]): record for record in records}
        self._write_json(index_dir / "manifest.json", manifest)
        self._write_jsonl(index_dir / "records.jsonl", records)
        self._write_json(index_dir / "records.json", records)
        self._write_jsonl(index_dir / "stix_objects.jsonl", source_objects)
        self._write_json(index_dir / "stix_object_locator.json", self._stix_object_locator(source_objects))
        self._write_json(index_dir / "completeness_report.json", completeness)
        self._write_json(index_dir / "by_technique_id.json", by_technique_id)
        self._write_json(index_dir / "by_tactic.json", self._group_by_list_field(records, "tactic"))
        self._write_json(index_dir / "by_platform.json", self._group_by_list_field(records, "platforms"))
        self._write_json(index_dir / "by_data_source.json", self._group_by_list_field(records, "data_sources"))
        self._write_jsonl(index_dir / "relationships.jsonl", relationships_flat)

    def _index_summary(
        self,
        index_dir: Path,
        source_path: Path,
        spec: AttackIndexSpec,
        source_sha256: str,
        objects: list[dict[str, Any]],
        source_objects: list[dict[str, object]],
        records: list[dict[str, Any]],
        relationships_flat: list[dict[str, object]],
    ) -> dict[str, object]:
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
