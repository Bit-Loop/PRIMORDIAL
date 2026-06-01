from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from primordial.labs.ctf import load_ctf_lab_phase_catalog, load_ctf_phase_target_manifests


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "catalog" / "labs" / "ctf_lab_phases.yaml"


class CTFPhaseTargetManifestTests(unittest.TestCase):
    def test_phase_target_loader_accepts_mbptl_manifest_for_phase_three(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(3)

        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = Path(temp_dir) / "mbptl-web-cache.json"
            target_path.write_text(json.dumps(_mbptl_manifest()), encoding="utf-8")

            target_set = load_ctf_phase_target_manifests(phase, [target_path])

        self.assertEqual(target_set.phase_number, 3)
        self.assertEqual(target_set.phase_id, "phase_3_mbptl")
        self.assertEqual(target_set.target_ids, ("mbptl-web-cache",))
        self.assertEqual(target_set.targets[0].target_family, "mbptl")
        self.assertEqual(target_set.exit_gates, ("phase_targets_loaded_from_manifests",))

    def test_phase_target_loader_rejects_family_outside_phase_scope(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(3)
        manifest = _mbptl_manifest()
        manifest["target_family"] = "vulhub_cve_labs"
        manifest["vulnerability"] = {
            "cve_id": "CVE-2021-41773",
            "product": "Apache httpd",
            "affected_versions": ["2.4.49"],
            "fixed_versions": ["2.4.51"],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = Path(temp_dir) / "wrong-family.json"
            target_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "target_family"):
                load_ctf_phase_target_manifests(phase, [target_path])

    def test_phase_target_loader_rejects_duplicate_target_ids(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(3)

        with tempfile.TemporaryDirectory() as temp_dir:
            first = Path(temp_dir) / "first.json"
            second = Path(temp_dir) / "second.json"
            first.write_text(json.dumps(_mbptl_manifest()), encoding="utf-8")
            second.write_text(json.dumps(_mbptl_manifest()), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_ctf_phase_target_manifests(phase, [first, second])

    def test_phase_target_loader_requires_at_least_one_manifest(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(3)

        with self.assertRaisesRegex(ValueError, "manifest"):
            load_ctf_phase_target_manifests(phase, [])


def _mbptl_manifest() -> dict[str, object]:
    return {
        "lab_id": "mbptl-web-cache",
        "title": "MBPTL Web Cache Target",
        "platform": "docker",
        "category": "web",
        "difficulty": "intermediate",
        "target_family": "mbptl",
        "source": {
            "repo_url": "https://github.com/PortSwigger/web-security-academy",
            "path": "labs/web-cache",
        },
        "scope": {
            "network": "lab_mbptl_web_cache",
            "assets": ["http://127.0.0.1:3190"],
        },
        "provisioning": {
            "mode": "docker",
            "compose_project": "mbptl_web_cache",
            "network": "lab_mbptl_web_cache",
            "published_ports": [{"host": 3190, "container": 80}],
        },
        "evidence": {"required": ["http_request", "http_response", "scoring_result"]},
        "policy": {"default_intent": "recon_only"},
    }


if __name__ == "__main__":
    unittest.main()
