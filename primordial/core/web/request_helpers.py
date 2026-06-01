from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from primordial.core.web.responses import WebResponse


class WebRequestHelpersMixin:
    def _target_asset_rows(
        self,
        handle: str,
        active_ip: str | None,
        assets: list[Any],
    ) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        seen: set[str] = set()

        def add(asset: str, asset_type: str | None = None, metadata: dict[str, object] | None = None) -> None:
            raw_asset = str(asset or "").strip()
            if not raw_asset or raw_asset in seen:
                return
            seen.add(raw_asset)
            row: dict[str, object] = {"asset": raw_asset, "asset_type": asset_type or self.runtime._infer_asset_type(raw_asset)}
            if metadata:
                row["metadata"] = metadata
            rows.append(row)

        add(handle, "hostname")
        for item in assets:
            if isinstance(item, dict):
                add(
                    str(item.get("asset") or ""),
                    str(item.get("asset_type") or "") or None,
                    dict(item.get("metadata", {})) if isinstance(item.get("metadata"), dict) else None,
                )
            else:
                add(str(item or ""))
        if active_ip:
            add(active_ip, "ip", {"active": True, "operator_confirmed": True})
        return rows or [{"asset": handle, "asset_type": "hostname"}]

    def _static_asset_response(self, raw_path: str) -> WebResponse | None:
        asset = unquote(raw_path.lstrip("/"))
        if not asset or asset.endswith("/"):
            return self._static_response("index.html", "text/html; charset=utf-8")
        path = (self._static_dir / asset).resolve()
        try:
            path.relative_to(self._static_dir.resolve())
        except ValueError:
            return self._json_response({"error": "not found", "path": raw_path}, status=404)
        if not path.is_file():
            return self._static_response("index.html", "text/html; charset=utf-8")
        return self._file_response(path, self._content_type(path))

    def _static_response(self, filename: str, content_type: str) -> WebResponse:
        path = self._static_dir / filename
        if not path.exists():
            return self._json_response({"error": "asset missing", "asset": filename}, status=404)
        return self._file_response(path, content_type)

    def _file_response(self, path: Path, content_type: str) -> WebResponse:
        return WebResponse(
            status=200,
            body=path.read_bytes(),
            content_type=content_type,
            headers={"Cache-Control": "no-store"},
        )

    def _content_type(self, path: Path) -> str:
        suffix = path.suffix.lower()
        if suffix == ".html":
            return "text/html; charset=utf-8"
        if suffix == ".js":
            return "text/javascript; charset=utf-8"
        if suffix == ".css":
            return "text/css; charset=utf-8"
        if suffix == ".json":
            return "application/json; charset=utf-8"
        if suffix == ".svg":
            return "image/svg+xml"
        if suffix == ".png":
            return "image/png"
        if suffix in {".jpg", ".jpeg"}:
            return "image/jpeg"
        if suffix == ".woff2":
            return "font/woff2"
        return "application/octet-stream"

    def _json_response(self, payload: dict[str, Any], status: int = 200) -> WebResponse:
        return WebResponse(
            status=status,
            body=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
            content_type="application/json; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    def _parse_json_body(self, body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("invalid JSON payload") from exc
        if not isinstance(payload, dict):
            raise ValueError("JSON payload must be an object")
        return payload

    def _int_param(self, query: dict[str, list[str]], name: str, default: int) -> int:
        raw = query.get(name, [])
        if not raw:
            return default
        try:
            return max(1, int(raw[0]))
        except ValueError:
            return default

    def _bool_param(self, query: dict[str, list[str]], name: str, default: bool) -> bool:
        raw = query.get(name, [])
        if not raw:
            return default
        return raw[0].strip().lower() in {"1", "true", "yes", "on"}

    def _optional_string(self, payload: dict[str, Any], key: str) -> str | None:
        value = payload.get(key)
        if value is None:
            return None
        return str(value).strip() or None

    def _optional_int(self, payload: dict[str, Any], key: str) -> int | None:
        value = payload.get(key)
        if value is None or value == "":
            return None
        return int(value)

    def _payload_list(self, payload: dict[str, Any], key: str) -> list[str]:
        value = payload.get(key)
        if value is None:
            return []
        if isinstance(value, list | tuple | set):
            return [str(item).strip() for item in value if str(item).strip()]
        return [str(value).strip()] if str(value).strip() else []

    def _rag_filters_payload(self, payload: dict[str, Any]) -> dict[str, object]:
        raw = payload.get("filters")
        filters: dict[str, object] = dict(raw) if isinstance(raw, dict) else {}
        for key in (
            "domain",
            "source_file",
            "doc_id",
            "chunk_type",
            "card_type",
            "risk_family",
            "output_mode",
            "source_priority",
            "vuln_id",
            "cve_id",
            "ghsa_id",
            "osv_id",
            "alias",
            "ecosystem",
            "package",
            "vendor",
            "product",
            "cpe",
            "purl",
            "cwe",
            "cvss_severity",
            "source_kind",
            "safety_level",
        ):
            values = self._payload_list(payload, key)
            if values:
                filters[key] = values
        if "requires_authorized_scope" in payload:
            filters["requires_authorized_scope"] = bool(payload.get("requires_authorized_scope"))
        for key in ("kev", "fixed_version_known", "asset_match", "watchlist_match"):
            if key in payload:
                filters[key] = bool(payload.get(key))
        for key in ("epss_probability", "epss_percentile"):
            if key in payload:
                filters[key] = payload.get(key)
        return filters

    def _rag_chunk_api_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = dict(payload)
        embedding = result.get("embedding")
        if isinstance(embedding, dict):
            result["embedding"] = {
                key: value
                for key, value in embedding.items()
                if key not in {"embedding", "vector", "values"}
            }
        return result

    def _optional_query_string(self, query: dict[str, list[str]], key: str) -> str | None:
        values = query.get(key, [])
        if not values:
            return None
        return values[0].strip() or None
