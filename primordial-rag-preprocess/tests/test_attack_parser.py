from __future__ import annotations

import json

from primordial_preprocess.extraction.json_attack import parse_attack_file


def test_attack_parser_emits_structured_technique_record(tmp_path):
    path = tmp_path / "enterprise-attack.json"
    path.write_text(
        json.dumps(
            {
                "objects": [
                    {
                        "type": "attack-pattern",
                        "id": "attack-pattern--1",
                        "name": "Example Technique",
                        "description": "Technique description.",
                        "modified": "2026-01-01T00:00:00.000Z",
                        "x_mitre_version": "1.0",
                        "kill_chain_phases": [{"phase_name": "discovery"}],
                        "x_mitre_platforms": ["Linux"],
                        "x_mitre_detection": "Look for example telemetry.",
                        "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
                    },
                    {
                        "type": "course-of-action",
                        "id": "course-of-action--1",
                        "name": "Example Mitigation",
                        "description": "Mitigation description.",
                        "external_references": [{"source_name": "mitre-attack", "external_id": "M0001"}],
                    },
                    {
                        "type": "relationship",
                        "id": "relationship--1",
                        "relationship_type": "mitigates",
                        "source_ref": "course-of-action--1",
                        "target_ref": "attack-pattern--1",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    records = parse_attack_file(path)

    assert len(records) == 3
    record = next(item for item in records if item["object_type"] == "attack-pattern")
    assert record["attack_domain"] == "enterprise"
    assert record["technique_id"] == "T0001"
    assert record["tactics"] == ["discovery"]
    assert record["platforms"] == ["Linux"]
    assert record["mitigations"][0]["mitigation_id"] == "M0001"
    assert record["source_object"]["name"] == "Example Technique"
    assert {item["object_type"] for item in records} == {"attack-pattern", "course-of-action", "relationship"}
