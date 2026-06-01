from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from primordial.core.rag.attack import AttackIndexPreprocessor


class AttackIndexPreprocessorTests(unittest.TestCase):
    def test_preprocesses_attack_stix_into_structured_indexes_without_vectorization(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_dir = root / "src"
            output_root = root / "out"
            source_dir.mkdir()
            for filename, domain, technique_id in (
                ("mitre-enterprise-attack.json", "enterprise-attack", "T1000"),
                ("mitre-mobile-attack.json", "mobile-attack", "T2000"),
                ("mitre-ics-attack.json", "ics-attack", "T3000"),
            ):
                (source_dir / filename).write_text(
                    json.dumps(self._bundle(domain=domain, technique_id=technique_id)),
                    encoding="utf-8",
                )

            payload = AttackIndexPreprocessor().preprocess(source_dir=source_dir, output_root=output_root)

            self.assertFalse(payload["raw_vectorized"])
            self.assertFalse(payload["structured_records_vectorized"])
            self.assertEqual(
                {item["index_name"] for item in payload["indexes"]},
                {"attck_enterprise_index", "attck_mobile_index", "attck_ics_index"},
            )
            enterprise_manifest = json.loads((output_root / "attck_enterprise_index" / "manifest.json").read_text())
            completeness = json.loads(
                (output_root / "attck_enterprise_index" / "completeness_report.json").read_text()
            )
            enterprise_records = [
                json.loads(line)
                for line in (output_root / "attck_enterprise_index" / "records.jsonl").read_text().splitlines()
            ]
            source_objects = [
                json.loads(line)
                for line in (output_root / "attck_enterprise_index" / "stix_objects.jsonl").read_text().splitlines()
            ]
            locator = json.loads((output_root / "attck_enterprise_index" / "stix_object_locator.json").read_text())
            by_tactic = json.loads((output_root / "attck_enterprise_index" / "by_tactic.json").read_text())
            by_platform = json.loads((output_root / "attck_enterprise_index" / "by_platform.json").read_text())
            by_data_source = json.loads((output_root / "attck_enterprise_index" / "by_data_source.json").read_text())

            self.assertEqual(enterprise_manifest["index_mode"], "structured_attck_records")
            self.assertFalse(enterprise_manifest["raw_vectorized"])
            self.assertTrue(enterprise_manifest["lossless_source_objects"])
            self.assertTrue(completeness["source_objects_complete"])
            self.assertTrue(completeness["technique_records_complete"])
            self.assertEqual(completeness["source_object_count"], len(source_objects))
            self.assertEqual(enterprise_records[0]["technique_id"], "T1000")
            self.assertEqual(enterprise_records[0]["name"], "Fixture Technique")
            self.assertEqual(enterprise_records[0]["source_object"]["id"], "attack-pattern--t1000")
            self.assertEqual(enterprise_records[0]["domain"], "enterprise-attack")
            self.assertEqual(enterprise_records[0]["tactic"], ["discovery"])
            self.assertEqual(enterprise_records[0]["platforms"], ["Windows"])
            self.assertEqual(
                enterprise_records[0]["data_sources"],
                ["Network Traffic", "Process: Process Creation"],
            )
            self.assertEqual(enterprise_records[0]["data_components"][0]["component_id"], "DC0001")
            self.assertEqual(enterprise_records[0]["detection"], "Look for fixture process creation.")
            self.assertEqual(enterprise_records[0]["mitigations"][0]["mitigation_id"], "M1000")
            self.assertTrue(any(item["relationship_type"] == "uses" for item in enterprise_records[0]["relationships"]))
            self.assertFalse(enterprise_records[0]["revoked"])
            self.assertFalse(enterprise_records[0]["deprecated"])
            self.assertEqual(enterprise_records[0]["version"], "1.0")
            self.assertIn("attack-pattern--t1000", locator)
            self.assertEqual(locator["attack-pattern--t1000"]["type"], "attack-pattern")
            self.assertEqual(by_tactic["discovery"], ["T1000"])
            self.assertEqual(by_platform["Windows"], ["T1000"])
            self.assertEqual(by_data_source["Process: Process Creation"], ["T1000"])
            self.assertIn("scope_decision", enterprise_records[0]["usage_policy"]["prohibited_uses"])

    def _bundle(self, *, domain: str, technique_id: str) -> dict[str, object]:
        refs = self._bundle_refs(technique_id)
        return {
            "type": "bundle",
            "id": f"bundle--{domain}",
            "spec_version": "2.1",
            "objects": [
                self._technique_object(domain, technique_id, refs["technique"]),
                self._data_component_object(refs["data_component"]),
                self._analytic_object(refs["analytic"], refs["data_component"]),
                self._detection_object(refs["detection"], refs["analytic"]),
                self._mitigation_object(refs["mitigation"]),
                self._group_object(refs["group"]),
                *self._relationship_objects(technique_id, refs),
            ],
        }

    def _bundle_refs(self, technique_id: str) -> dict[str, str]:
        suffix = technique_id.lower()
        return {
            "technique": f"attack-pattern--{suffix}",
            "mitigation": f"course-of-action--{suffix}",
            "group": f"intrusion-set--{suffix}",
            "detection": f"x-mitre-detection-strategy--{suffix}",
            "analytic": f"x-mitre-analytic--{suffix}",
            "data_component": f"x-mitre-data-component--{suffix}",
        }

    def _technique_object(self, domain: str, technique_id: str, technique_ref: str) -> dict[str, object]:
        return {
            "type": "attack-pattern",
            "id": technique_ref,
            "name": "Fixture Technique",
            "description": "Fixture behavior description.",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-02-01T00:00:00.000Z",
            "external_references": [{"source_name": "mitre-attack", "external_id": technique_id}],
            "kill_chain_phases": [{"kill_chain_name": domain, "phase_name": "discovery"}],
            "x_mitre_domains": [domain],
            "x_mitre_platforms": ["Windows"],
            "x_mitre_data_sources": ["Process: Process Creation"],
            "x_mitre_detection": "Look for fixture process creation.",
            "x_mitre_version": "1.0",
            "x_mitre_attack_spec_version": "3.3.0",
            "x_mitre_deprecated": False,
        }

    def _data_component_object(self, data_component_ref: str) -> dict[str, object]:
        return {
            "type": "x-mitre-data-component",
            "id": data_component_ref,
            "name": "Network Traffic",
            "description": "Network traffic events.",
            "external_references": [{"source_name": "mitre-attack", "external_id": "DC0001"}],
        }

    def _analytic_object(self, analytic_ref: str, data_component_ref: str) -> dict[str, object]:
        return {
            "type": "x-mitre-analytic",
            "id": analytic_ref,
            "name": "Analytic 0001",
            "external_references": [{"source_name": "mitre-attack", "external_id": "AN0001"}],
            "x_mitre_log_source_references": [
                {"x_mitre_data_component_ref": data_component_ref, "name": "NSM:Flow", "channel": "outbound connection"}
            ],
        }

    def _detection_object(self, detection_ref: str, analytic_ref: str) -> dict[str, object]:
        return {
            "type": "x-mitre-detection-strategy",
            "id": detection_ref,
            "name": "Fixture Detection Strategy",
            "external_references": [{"source_name": "mitre-attack", "external_id": "DET0001"}],
            "x_mitre_analytic_refs": [analytic_ref],
        }

    def _mitigation_object(self, mitigation_ref: str) -> dict[str, object]:
        return {
            "type": "course-of-action",
            "id": mitigation_ref,
            "name": "Fixture Mitigation",
            "description": "Mitigate the fixture behavior.",
            "external_references": [{"source_name": "mitre-attack", "external_id": "M1000"}],
        }

    def _group_object(self, group_ref: str) -> dict[str, object]:
        return {
            "type": "intrusion-set",
            "id": group_ref,
            "name": "Fixture Group",
            "external_references": [{"source_name": "mitre-attack", "external_id": "G1000"}],
        }

    def _relationship_objects(self, technique_id: str, refs: dict[str, str]) -> list[dict[str, object]]:
        suffix = technique_id.lower()
        return [
            {
                "type": "relationship",
                "id": f"relationship--detects-{suffix}",
                "relationship_type": "detects",
                "source_ref": refs["detection"],
                "target_ref": refs["technique"],
            },
            {
                "type": "relationship",
                "id": f"relationship--mitigates-{suffix}",
                "relationship_type": "mitigates",
                "source_ref": refs["mitigation"],
                "target_ref": refs["technique"],
            },
            {
                "type": "relationship",
                "id": f"relationship--uses-{suffix}",
                "relationship_type": "uses",
                "source_ref": refs["group"],
                "target_ref": refs["technique"],
                "description": "Fixture group uses fixture technique.",
            },
        ]


if __name__ == "__main__":
    unittest.main()
