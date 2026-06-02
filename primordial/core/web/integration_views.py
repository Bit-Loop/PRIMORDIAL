from __future__ import annotations

from typing import Any


class WebIntegrationViewsMixin:
    def _caido_view(self, status: dict[str, Any], records: dict[str, Any], targets: list[dict[str, Any]]) -> dict[str, Any]:
        presets_payload = self.runtime.caido_httpql_presets()
        imported_captures = []
        evidence_rows = records.get("evidence", []) if isinstance(records.get("evidence", []), list) else []
        for index, item in enumerate(evidence_rows):
            if not isinstance(item, dict) or str(item.get("type", "")).lower() != "http_replay":
                continue
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            caido_request_id = str(metadata.get("caido_request_id") or "")
            if not caido_request_id:
                continue
            imported_captures.append(
                {
                    "id": str(item.get("id") or f"imported_{index}"),
                    "caidoRequestId": caido_request_id,
                    "method": str(metadata.get("method") or "HTTP"),
                    "host": str(metadata.get("host") or ""),
                    "path": str(metadata.get("path") or item.get("title") or "/"),
                    "status": int(metadata.get("status_code", 0) or 0),
                    "length": int(metadata.get("response_length", 0) or 0),
                    "time": self._time_label(item.get("created_at")),
                    "source": "imported",
                    "mime": str(metadata.get("content_type") or ""),
                    "requestSnippet": "",
                    "responseSnippet": "",
                    "snippetsStored": bool(metadata.get("snippets_stored")),
                    "evidenceId": str(item.get("id") or ""),
                }
            )
        return {
            "connection": status,
            "requests": [],
            "importedCaptures": imported_captures[:50],
            "replays": [],
            "savedFilters": presets_payload.get("presets", []),
            "targetOptions": presets_payload.get("targets", []),
        }

    def _geo_view(self, targets: list[dict[str, Any]], caido_status: dict[str, Any], models: dict[str, Any]) -> dict[str, Any]:
        pins = [
            {
                "id": "g_self",
                "kind": "self",
                "label": "operator",
                "city": "local runtime",
                "country": "control-plane",
                "lat": 0.0,
                "lon": 0.0,
                "asn": "local",
                "org": "Primordial",
                "status": "live",
                "geolocated": False,
            }
        ]
        for index, row in enumerate(self._scope_view(targets)):
            lat, lon = self._synthetic_map_coordinate(index)
            pins.append(
                {
                    "id": f"g_target_{index}",
                    "kind": "target",
                    "label": row["handle"] if not row["ip"] else f"{row['handle']} ({row['ip']})",
                    "city": "unresolved",
                    "country": "scope",
                    "lat": lat,
                    "lon": lon,
                    "asn": "scope",
                    "org": row["profile"] or "scoped target",
                    "status": row["status"],
                    "geolocated": False,
                }
            )
        if caido_status.get("configured"):
            pins.append(
                {
                    "id": "g_caido",
                    "kind": "tool",
                    "label": "caido",
                    "city": "localhost",
                    "country": "control-plane",
                    "lat": 0.08,
                    "lon": -0.08,
                    "asn": "local",
                    "org": "Caido",
                    "status": "live" if caido_status.get("ok") else "idle",
                    "geolocated": False,
                }
            )
        if models.get("ollama", {}).get("ok"):
            pins.append(
                {
                    "id": "g_ollama",
                    "kind": "tool",
                    "label": "ollama",
                    "city": "localhost",
                    "country": "control-plane",
                    "lat": -0.08,
                    "lon": 0.08,
                    "asn": "local",
                    "org": "Ollama",
                    "status": "live",
                    "geolocated": False,
                }
            )
        return {
            "pins": pins,
            "traces": [{"from": "g_self", "to": pin["id"], "kind": "ok", "label": "scope"} for pin in pins if pin["id"] != "g_self"],
            "asns": [{"num": "local", "org": "Local runtime", "country": "local", "refs": len(pins), "role": "operator"}],
        }

    def _synthetic_map_coordinate(self, index: int) -> tuple[float, float]:
        offsets = [
            (0.12, 0.0),
            (0.0, 0.12),
            (-0.12, 0.0),
            (0.0, -0.12),
            (0.12, 0.12),
            (-0.12, 0.12),
            (-0.12, -0.12),
            (0.12, -0.12),
        ]
        lat, lon = offsets[index % len(offsets)]
        ring = index // len(offsets)
        if ring:
            lat += min(1.0, ring * 0.08)
            lon -= min(1.0, ring * 0.08)
        return lat, lon

    def _approval_chat_view(self, approvals: list[dict[str, Any]]) -> list[dict[str, str]]:
        if not approvals:
            return [{"who": "system", "t": self._time_label(None), "text": "No pending approvals."}]
        return [
            {
                "who": "system",
                "t": self._time_label(None),
                "text": f"Approval pending: {item['title']} ({item['id']})",
            }
            for item in approvals[:8]
        ]

    def _operator_chat_view(self) -> list[dict[str, str]]:
        try:
            messages = self.runtime.operator_chat_payload(limit=20).get("messages", [])
        except Exception:
            messages = []
        rows = []
        for item in messages if isinstance(messages, list) else []:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "who": "me" if item.get("role") == "operator" else "agent",
                    "t": self._time_label(item.get("created_at")),
                    "text": str(item.get("body") or ""),
                    "model": str(item.get("model") or ""),
                }
            )
        return rows or [{"who": "system", "t": self._time_label(None), "text": "Operator chat is ready."}]

    def _signals_view(self, audit: dict[str, Any]) -> list[str]:
        signals = [
            str(item.get("signal"))
            for item in audit.get("recent_runtime_events", []) if isinstance(item, dict) and item.get("signal")
        ]
        return signals[:20]
