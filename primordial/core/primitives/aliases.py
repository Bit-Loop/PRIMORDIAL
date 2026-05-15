from __future__ import annotations

from collections.abc import Iterable

from primordial.core.domain.models import PrimitiveManifest


PRIMITIVE_HINT_ALIASES: dict[str, str] = {
    "web-content-discovery": "content-discovery",
    "web-directory-enumeration": "content-discovery",
    "directory-enumeration": "content-discovery",
    "path-discovery": "content-discovery",
    "http-header-analysis": "http-probe",
    "http-analysis": "http-probe",
    "web-probe": "http-probe",
    "service-version-detection": "tcp-service-discovery",
    "service-version-fingerprinting": "tcp-service-discovery",
    "service-fingerprinting": "tcp-service-discovery",
    "service-detection": "tcp-service-discovery",
    "service-identification": "tcp-service-discovery",
    "tcp-service-fingerprinting": "tcp-service-discovery",
}


def normalize_primitive_hint(value: object) -> str:
    hint = str(value or "").strip().lower().replace("_", "-")
    return PRIMITIVE_HINT_ALIASES.get(hint, hint)


def primitives_for_hint(
    manifests: Iterable[PrimitiveManifest],
    hint: object,
) -> list[PrimitiveManifest]:
    canonical = normalize_primitive_hint(hint)
    if not canonical:
        return []
    manifest_list = list(manifests)
    exact = [
        manifest
        for manifest in manifest_list
        if manifest.name.lower() == canonical
    ]
    if exact:
        return exact
    selected: dict[str, PrimitiveManifest] = {}
    for manifest in manifest_list:
        capability_tags = {tag.lower() for tag in manifest.capability_tags}
        if canonical in capability_tags:
            selected.setdefault(manifest.name, manifest)
    return list(selected.values())
