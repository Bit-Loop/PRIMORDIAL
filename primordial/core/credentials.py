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
    KNOWN_CREDENTIAL_KEYS = {"username", "password", "domain"}
    FIELDS = (
        CredentialField("notion", "api_key", "NOTION_API_KEY"),
        CredentialField("notion", "parent_page_id", "NOTION_PARENT_PAGE_ID"),
        CredentialField("notion", "version", "NOTION_VERSION"),
        CredentialField("discord", "webhook_url", "DISCORD_WEBHOOK_URL"),
        CredentialField("known", "username", "PRIMORDIAL_KNOWN_USERNAME"),
        CredentialField("known", "password", "PRIMORDIAL_KNOWN_PASSWORD"),
        CredentialField("known", "domain", "PRIMORDIAL_KNOWN_DOMAIN"),
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
        payload = self._read()
        alias = self._known_credentials_alias_field(field)
        fields = [field]
        if alias is not None:
            fields = [alias, field] if field.service == "lab" else [field, alias]
        for candidate in fields:
            value = self._field_value(payload, candidate)
            if value:
                return value
        return ""

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
        result: dict[str, object] = {"path": str(self.path), "services": {}}
        for field in self.FIELDS:
            service_status = result["services"].setdefault(field.service, {})  # type: ignore[union-attr]
            source, value, stored_entry = self._field_status_value(payload, field)
            service_status[field.key] = {
                "configured": bool(value),
                "source": source,
                "hint": self._status_hint(field, value),
                "updated_at": stored_entry.get("updated_at") if isinstance(stored_entry, dict) and value else None,
            }
        return result

    def _field(self, service: str, key: str) -> CredentialField:
        for field in self.FIELDS:
            if field.service == service and field.key == key:
                return field
        raise ValueError(f"unsupported credential field: {service}.{key}")

    def _field_value(self, payload: dict[str, Any], field: CredentialField) -> str:
        if field.env_name:
            env_value = os.getenv(field.env_name, "").strip()
            if env_value:
                return env_value
        services = payload.get("services", {})
        stored_entry = services.get(field.service, {}).get(field.key, {}) if isinstance(services, dict) else {}
        stored_value = str(stored_entry.get("value", "")).strip() if isinstance(stored_entry, dict) else ""
        return stored_value

    def _field_status_value(self, payload: dict[str, Any], field: CredentialField) -> tuple[str, str, dict[str, Any]]:
        source, value, stored_entry = self._direct_field_status_value(payload, field)
        if value:
            return source, value, stored_entry
        alias = self._known_credentials_alias_field(field)
        if alias is None:
            return source, value, stored_entry
        alias_source, alias_value, alias_entry = self._direct_field_status_value(payload, alias)
        if not alias_value:
            return source, value, stored_entry
        return f"{alias_source}_alias:{alias.service}", alias_value, alias_entry

    def _direct_field_status_value(
        self,
        payload: dict[str, Any],
        field: CredentialField,
    ) -> tuple[str, str, dict[str, Any]]:
        services = payload.get("services", {})
        stored_entry = services.get(field.service, {}).get(field.key, {}) if isinstance(services, dict) else {}
        if field.env_name:
            env_value = os.getenv(field.env_name, "").strip()
            if env_value:
                return "environment", env_value, stored_entry if isinstance(stored_entry, dict) else {}
        stored_value = str(stored_entry.get("value", "")).strip() if isinstance(stored_entry, dict) else ""
        if stored_value:
            return "local_store", stored_value, stored_entry
        return "missing", "", stored_entry if isinstance(stored_entry, dict) else {}

    def _known_credentials_alias_field(self, field: CredentialField) -> CredentialField | None:
        if field.key not in self.KNOWN_CREDENTIAL_KEYS:
            return None
        if field.service == "known":
            return self._field("lab", field.key)
        if field.service == "lab":
            return self._field("known", field.key)
        return None

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
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                tmp_path.unlink()
            finally:
                raise
        os.replace(tmp_path, self.path)
        self.path.chmod(0o600)
        try:
            dir_fd = os.open(self.path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _status_hint(self, field: CredentialField, value: str) -> str:
        if not value:
            return ""
        if field.key == "username":
            return value
        return self._redact(value)

    def _redact(self, value: str) -> str:
        if not value:
            return ""
        if len(value) <= 2:
            return "*" * len(value)
        if len(value) <= 8:
            return f"{value[:1]}...{value[-1:]}"
        return f"{value[:4]}...{value[-4:]}"
