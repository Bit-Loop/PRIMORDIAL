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
        technique_ref = f"attack-pattern--{technique_id.lower()}"
        mitigation_ref = f"course-of-action--{technique_id.lower()}"
        group_ref = f"intrusion-set--{technique_id.lower()}"
        detection_ref = f"x-mitre-detection-strategy--{technique_id.lower()}"
        analytic_ref = f"x-mitre-analytic--{technique_id.lower()}"
        data_component_ref = f"x-mitre-data-component--{technique_id.lower()}"
        return {
            "type": "bundle",
            "id": f"bundle--{domain}",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": technique_ref,
                    "name": "Fixture Technique",
                    "description": "Fixture behavior description.",
                    "created": "2026-01-01T00:00:00.000Z",
                    "modified": "2026-02-01T00:00:00.000Z",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": technique_id},
                    ],
                    "kill_chain_phases": [
                        {"kill_chain_name": domain, "phase_name": "discovery"},
                    ],
                    "x_mitre_domains": [domain],
                    "x_mitre_platforms": ["Windows"],
                    "x_mitre_data_sources": ["Process: Process Creation"],
                    "x_mitre_detection": "Look for fixture process creation.",
                    "x_mitre_version": "1.0",
                    "x_mitre_attack_spec_version": "3.3.0",
                    "x_mitre_deprecated": False,
                },
                {
                    "type": "x-mitre-data-component",
                    "id": data_component_ref,
                    "name": "Network Traffic",
                    "description": "Network traffic events.",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "DC0001"},
                    ],
                },
                {
                    "type": "x-mitre-analytic",
                    "id": analytic_ref,
                    "name": "Analytic 0001",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "AN0001"},
                    ],
                    "x_mitre_log_source_references": [
                        {
                            "x_mitre_data_component_ref": data_component_ref,
                            "name": "NSM:Flow",
                            "channel": "outbound connection",
                        }
                    ],
                },
                {
                    "type": "x-mitre-detection-strategy",
                    "id": detection_ref,
                    "name": "Fixture Detection Strategy",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "DET0001"},
                    ],
                    "x_mitre_analytic_refs": [analytic_ref],
                },
                {
                    "type": "course-of-action",
                    "id": mitigation_ref,
                    "name": "Fixture Mitigation",
                    "description": "Mitigate the fixture behavior.",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "M1000"},
                    ],
                },
                {
                    "type": "intrusion-set",
                    "id": group_ref,
                    "name": "Fixture Group",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "G1000"},
                    ],
                },
                {
                    "type": "relationship",
                    "id": f"relationship--detects-{technique_id.lower()}",
                    "relationship_type": "detects",
                    "source_ref": detection_ref,
                    "target_ref": technique_ref,
                },
                {
                    "type": "relationship",
                    "id": f"relationship--mitigates-{technique_id.lower()}",
                    "relationship_type": "mitigates",
                    "source_ref": mitigation_ref,
                    "target_ref": technique_ref,
                },
                {
                    "type": "relationship",
                    "id": f"relationship--uses-{technique_id.lower()}",
                    "relationship_type": "uses",
                    "source_ref": group_ref,
                    "target_ref": technique_ref,
                    "description": "Fixture group uses fixture technique.",
                },
            ],
        }


if __name__ == "__main__":
    unittest.main()
