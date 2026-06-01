from __future__ import annotations

from typing import Any

from primordial.core.rag.attack_types import ATTCK_ALLOWED_USES, ATTCK_PROHIBITED_USES


class AttackRecordMixin:
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
        technique_ref = str(technique.get("id"))
        data_sources, data_components = self._data_sources_for_technique(
            technique,
            technique_ref=technique_ref,
            relationships=relationships,
            by_ref=by_ref,
        )
        domains = technique.get("x_mitre_domains", [])
        selected_domain = str(domains[0]) if isinstance(domains, list) and domains else domain
        return {
            "technique_id": technique_id,
            "stix_id": technique_ref,
            "name": str(technique.get("name") or ""),
            "domain": selected_domain,
            "tactic": self._tactics(technique),
            "description": str(technique.get("description") or ""),
            "platforms": self._string_list(technique.get("x_mitre_platforms")),
            "data_sources": data_sources,
            "data_components": data_components,
            "detection": str(technique.get("x_mitre_detection") or ""),
            "mitigations": self._mitigations_for(technique_ref, relationships, by_ref),
            "relationships": self._relationships_for(technique_ref, relationships=relationships, by_ref=by_ref),
            "revoked": bool(technique.get("revoked")),
            "deprecated": bool(technique.get("x_mitre_deprecated")),
            "version": str(technique.get("x_mitre_version") or ""),
            "source_date": str(technique.get("modified") or technique.get("created") or ""),
            "created": str(technique.get("created") or ""),
            "modified": str(technique.get("modified") or ""),
            "attack_spec_version": str(technique.get("x_mitre_attack_spec_version") or ""),
            "source_sha256": source_sha256,
            "source_object_sha256": self._object_sha256(technique),
            "source_object": technique,
            "usage_policy": {"allowed_uses": ATTCK_ALLOWED_USES, "prohibited_uses": ATTCK_PROHIBITED_USES},
        }

    def _tactics(self, technique: dict[str, Any]) -> list[str]:
        return [
            str(item.get("phase_name"))
            for item in technique.get("kill_chain_phases", [])
            if isinstance(item, dict) and item.get("phase_name")
        ]

    def _mitigations_for(
        self,
        technique_ref: str,
        relationships: list[dict[str, Any]],
        by_ref: dict[str, dict[str, Any]],
    ) -> list[dict[str, object]]:
        mitigations = [
            self._mitigation_record(rel, by_ref)
            for rel in relationships
            if rel.get("relationship_type") == "mitigates" and rel.get("target_ref") == technique_ref
        ]
        return [item for item in mitigations if item is not None]

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
            self._add_detection_components(components, names, seen_components, rel=rel, by_ref=by_ref)
        return sorted(names), sorted(components, key=lambda item: (str(item["name"]), str(item["log_source"])))

    def _add_detection_components(
        self,
        components: list[dict[str, object]],
        names: set[str],
        seen_components: set[tuple[str, str, str, str]],
        *,
        rel: dict[str, Any],
        by_ref: dict[str, dict[str, Any]],
    ) -> None:
        detector_ref = str(rel.get("source_ref") or "")
        detector = by_ref.get(detector_ref, {})
        detector_type = str(detector.get("type") or "")
        if detector_type == "x-mitre-data-component":
            self._add_data_component(components, names, seen_components, component=detector, log_source={}, analytic={}, detection_strategy={})
            return
        if detector_type == "x-mitre-detection-strategy":
            self._add_strategy_components(components, names, seen_components, detector=detector, by_ref=by_ref)

    def _add_strategy_components(
        self,
        components: list[dict[str, object]],
        names: set[str],
        seen_components: set[tuple[str, str, str, str]],
        *,
        detector: dict[str, Any],
        by_ref: dict[str, dict[str, Any]],
    ) -> None:
        for analytic_ref in self._string_list(detector.get("x_mitre_analytic_refs")):
            analytic = by_ref.get(analytic_ref, {})
            log_sources = analytic.get("x_mitre_log_source_references", [])
            if not isinstance(log_sources, list):
                continue
            for log_source in log_sources:
                if isinstance(log_source, dict):
                    component = by_ref.get(str(log_source.get("x_mitre_data_component_ref") or ""), {})
                    self._add_data_component(components, names, seen_components, component=component, log_source=log_source, analytic=analytic, detection_strategy=detector)

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
        key = (str(component.get("id") or ""), component_name, log_name, channel)
        if key in seen:
            return
        seen.add(key)
        components.append(self._data_component_record(component, log_source, analytic, detection_strategy, component_name, log_name, channel))

    def _data_component_record(
        self,
        component: dict[str, Any],
        log_source: dict[str, Any],
        analytic: dict[str, Any],
        detection_strategy: dict[str, Any],
        component_name: str,
        log_name: str,
        channel: str,
    ) -> dict[str, object]:
        return {
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
            items.append(self._relationship_record(rel, source_ref=source_ref, target_ref=target_ref, technique_ref=technique_ref, by_ref=by_ref))
        return items

    def _relationship_record(
        self,
        rel: dict[str, Any],
        *,
        source_ref: str,
        target_ref: str,
        technique_ref: str,
        by_ref: dict[str, dict[str, Any]],
    ) -> dict[str, object]:
        other_ref = target_ref if source_ref == technique_ref else source_ref
        other = by_ref.get(other_ref, {})
        return {
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
