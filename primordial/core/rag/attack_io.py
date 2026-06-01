from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from primordial.core.rag.attack_types import AttackIndexSpec, AttackPreprocessError


class AttackIndexIOMixin:
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
                if key:
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
