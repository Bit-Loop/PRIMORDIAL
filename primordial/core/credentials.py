from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any

from primordial.core.domain.models import utc_now


@dataclass(frozen=True, slots=True)
class CredentialField:
    service: str
    key: str
    env_name: str | None = None


class CredentialStore:
    FIELDS = (
        CredentialField("notion", "api_key", "NOTION_API_KEY"),
        CredentialField("notion", "parent_page_id", "NOTION_PARENT_PAGE_ID"),
        CredentialField("notion", "version", "NOTION_VERSION"),
        CredentialField("discord", "webhook_url", "DISCORD_WEBHOOK_URL"),
        CredentialField("lab", "username", "PRIMORDIAL_LAB_USERNAME"),
        CredentialField("lab", "password", "PRIMORDIAL_LAB_PASSWORD"),
        CredentialField("lab", "domain", "PRIMORDIAL_LAB_DOMAIN"),
        CredentialField("caido", "graphql_url", "PRIMORDIAL_CAIDO_GRAPHQL_URL"),
        CredentialField("caido", "api_token", "PRIMORDIAL_CAIDO_API_TOKEN"),
    )

    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.parent.chmod(0o700)
        if self.path.exists():
            self.path.chmod(0o600)
            payload = self._read()
            services = payload.setdefault("services", {})
            if "web" in services:
                del services["web"]
                payload["updated_at"] = utc_now().isoformat()
                self._write(payload)

    def get(self, service: str, key: str) -> str:
        field = self._field(service, key)
        if field.env_name:
            env_value = os.getenv(field.env_name, "").strip()
            if env_value:
                return env_value
        payload = self._read()
        value = payload.get("services", {}).get(service, {}).get(key, {}).get("value", "")
        return str(value).strip()

    def update_service(self, service: str, values: dict[str, str]) -> dict[str, object]:
        payload = self._read()
        services = payload.setdefault("services", {})
        service_payload = services.setdefault(service, {})
        changed: list[str] = []
        for key, value in values.items():
            self._field(service, key)
            stripped = value.strip()
            if not stripped:
                continue
            service_payload[key] = {
                "value": stripped,
                "updated_at": utc_now().isoformat(),
            }
            changed.append(key)
        if changed:
            payload["version"] = 1
            payload["updated_at"] = utc_now().isoformat()
            self._write(payload)
        return {"service": service, "changed": changed}

    def clear_service(self, service: str) -> bool:
        payload = self._read()
        services = payload.setdefault("services", {})
        existed = service in services
        if existed:
            del services[service]
            payload["updated_at"] = utc_now().isoformat()
            self._write(payload)
        return existed

    def status(self) -> dict[str, object]:
        payload = self._read()
        services = payload.get("services", {})
        result: dict[str, object] = {"path": str(self.path), "services": {}}
        for field in self.FIELDS:
            service_status = result["services"].setdefault(field.service, {})  # type: ignore[union-attr]
            env_value = os.getenv(field.env_name or "", "").strip() if field.env_name else ""
            stored_entry = services.get(field.service, {}).get(field.key, {})
            stored_value = str(stored_entry.get("value", "")).strip() if isinstance(stored_entry, dict) else ""
            value = env_value or stored_value
            source = "environment" if env_value else "local_store" if stored_value else "missing"
            service_status[field.key] = {
                "configured": bool(value),
                "source": source,
                "hint": self._redact(value),
                "updated_at": stored_entry.get("updated_at") if isinstance(stored_entry, dict) and stored_value else None,
            }
        return result

    def _field(self, service: str, key: str) -> CredentialField:
        for field in self.FIELDS:
            if field.service == service and field.key == key:
                return field
        raise ValueError(f"unsupported credential field: {service}.{key}")

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "services": {}}
        self.path.chmod(0o600)
        with self.path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise ValueError("credential store must contain a JSON object")
        payload.setdefault("version", 1)
        payload.setdefault("services", {})
        return payload

    def _write(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.parent.chmod(0o700)
        tmp_path = self.path.with_suffix(".tmp")
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
        except Exception:
            try:
                tmp_path.unlink()
            finally:
                raise
        os.replace(tmp_path, self.path)
        self.path.chmod(0o600)

    def _redact(self, value: str) -> str:
        if not value:
            return ""
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}...{value[-4:]}"
