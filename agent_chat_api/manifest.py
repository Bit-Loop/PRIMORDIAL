from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class GeneratedMarkdownPolicy:
    path: str
    ingest_allowed: bool
    operational_retrieval_allowed: bool


@dataclass(frozen=True, slots=True)
class ServiceManifest:
    service_id: str
    runtime_boundary: str
    default_provider: str
    fallback_providers: tuple[str, ...]
    endpoints: tuple[tuple[str, str], ...]
    provider_defaults: dict[str, Any]
    generated_markdown: GeneratedMarkdownPolicy


def load_service_manifest(path: Path | None = None) -> ServiceManifest:
    manifest_path = path or Path(__file__).with_name("service.json")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{manifest_path} must contain a JSON object")

    generated_markdown = _object(payload, "generated_markdown")
    endpoints = tuple(
        (str(endpoint["method"]).upper(), str(endpoint["path"]))
        for endpoint in _list(payload, "endpoints")
        if isinstance(endpoint, dict) and "method" in endpoint and "path" in endpoint
    )

    return ServiceManifest(
        service_id=_string(payload, "service_id"),
        runtime_boundary=_string(payload, "runtime_boundary"),
        default_provider=_string(payload, "default_provider"),
        fallback_providers=tuple(str(provider) for provider in _list(payload, "fallback_providers")),
        endpoints=endpoints,
        provider_defaults=_object(payload, "provider_defaults"),
        generated_markdown=GeneratedMarkdownPolicy(
            path=_string(generated_markdown, "path"),
            ingest_allowed=_bool(generated_markdown, "ingest_allowed"),
            operational_retrieval_allowed=_bool(generated_markdown, "operational_retrieval_allowed"),
        ),
    )


def _string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _bool(payload: dict[str, Any], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _list(payload: dict[str, Any], key: str) -> list[Any]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a list")
    return value


def _object(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be an object")
    return value
