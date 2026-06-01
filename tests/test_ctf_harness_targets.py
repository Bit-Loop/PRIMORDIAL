from __future__ import annotations

import json
import tempfile
from pathlib import Path
import unittest

from primordial.labs.ctf import CTFTarget, load_ctf_target_manifest, load_ctf_target_manifest_file
from tests.support import fixture_flag


class CTFTargetManifestTests(unittest.TestCase):
    def test_ctf_target_manifest_preserves_scope_reset_and_closed_book_policy(self) -> None:
        manifest = {
            "lab_id": "juice-shop-foundation",
            "title": "OWASP Juice Shop Foundation",
            "platform": "docker",
            "category": "web",
            "difficulty": "foundation",
            "source": {
                "repo_url": "https://github.com/juice-shop/juice-shop",
                "ctf_export_repo_url": "https://github.com/juice-shop/juice-shop-ctf",
            },
            "scope": {
                "network": "lab_js_foundation",
                "assets": ["http://127.0.0.1:3100"],
            },
            "provisioning": {
                "mode": "docker",
                "compose_project": "js_foundation",
                "network": "lab_js_foundation",
                "published_ports": [{"host": 3100, "container": 3000}],
            },
            "ctfd": {
                "challenge_id": "juice-shop-foundation",
                "hidden_until_runtime": True,
            },
            "closed_book": {
                "strip_paths": ["docs/", "solutions/", "writeups/"],
                "writeup_access_policy": "postmortem_only",
            },
            "mutation": {"enabled": True, "seed_source": "hmac"},
            "evidence": {"required": ["http_request", "http_response"]},
            "policy": {"default_intent": "recon_only"},
        }

        target = load_ctf_target_manifest(manifest)

        self.assertIsInstance(target, CTFTarget)
        self.assertEqual(target.id, "juice-shop-foundation")
        self.assertEqual(target.name, "OWASP Juice Shop Foundation")
        self.assertEqual(target.platform, "docker")
        self.assertEqual(target.scope.network, "lab_js_foundation")
        self.assertEqual(target.scope.assets, ("http://127.0.0.1:3100",))
        self.assertEqual(target.reset.mode, "docker")
        self.assertEqual(target.reset.network, "lab_js_foundation")
        self.assertEqual(target.writeup_access_policy, "postmortem_only")
        self.assertEqual(target.closed_book.strip_paths, ("docs/", "solutions/", "writeups/"))
        self.assertEqual(target.default_intent, "recon_only")
        self.assertEqual(target.evidence_expectations.required, ("http_request", "http_response"))
        self.assertEqual(target.scoreboard_ref["challenge_id"], "juice-shop-foundation")

    def test_local_container_manifest_selects_local_ctf_default_intent(self) -> None:
        manifest = {
            "lab_id": "local-container-target",
            "title": "Local Container Target",
            "platform": "docker",
            "category": "web",
            "difficulty": "foundation",
            "scope": {"network": "lab_local_container", "assets": ["http://127.0.0.1:3116"]},
            "provisioning": {"mode": "docker", "network": "lab_local_container"},
            "allowed_engagement_profiles": ["co_internal_lab"],
        }

        target = load_ctf_target_manifest(manifest)

        self.assertEqual(target.default_intent, "local_ctf_container")

    def test_ctf_target_manifest_rejects_hidden_expected_flags(self) -> None:
        manifest = {
            "lab_id": "unsafe-target",
            "title": "Unsafe Target",
            "platform": "docker",
            "category": "web",
            "difficulty": "foundation",
            "scope": {"network": "unsafe_lab", "assets": ["http://127.0.0.1:3101"]},
            "provisioning": {"mode": "docker", "network": "unsafe_lab"},
            "success_condition": {"type": "flag", "expected_flag": fixture_flag("hidden-answer").upper()},
            "policy": {"default_intent": "recon_only"},
        }

        with self.assertRaisesRegex(ValueError, "expected_flag"):
            load_ctf_target_manifest(manifest)

    def test_ctf_target_manifest_rejects_display_hidden_flag_keys(self) -> None:
        manifest = {
            "lab_id": "display-hidden-target",
            "title": "Display Hidden Target",
            "platform": "docker",
            "category": "web",
            "difficulty": "foundation",
            "scope": {"network": "display_hidden_lab", "assets": ["http://127.0.0.1:3114"]},
            "provisioning": {"mode": "docker", "network": "display_hidden_lab"},
            "success_condition": {"Expected Flag": "redacted-hidden-answer"},
            "policy": {"default_intent": "recon_only"},
        }

        with self.assertRaisesRegex(ValueError, "Expected Flag"):
            load_ctf_target_manifest(manifest)

    def test_ctf_target_manifest_rejects_raw_flag_like_values(self) -> None:
        manifest = {
            "lab_id": "raw-flag-value-target",
            "title": "Raw Flag Value Target",
            "platform": "docker",
            "category": "web",
            "difficulty": "foundation",
            "scope": {"network": "raw_flag_value_lab", "assets": ["http://127.0.0.1:3115"]},
            "provisioning": {"mode": "docker", "network": "raw_flag_value_lab"},
            "success_condition": {"proof_hint": "Submit " + fixture_flag("hidden-answer") + " to score."},
            "policy": {"default_intent": "recon_only"},
        }

        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            load_ctf_target_manifest(manifest)

    def test_ctf_target_manifest_rejects_public_scope_assets(self) -> None:
        manifest = {
            "lab_id": "public-target",
            "title": "Public Target",
            "platform": "docker",
            "category": "web",
            "difficulty": "foundation",
            "scope": {"network": "lab_public", "assets": ["https://example.com"]},
            "provisioning": {"mode": "docker", "network": "lab_public"},
            "policy": {"default_intent": "recon_only"},
        }

        with self.assertRaisesRegex(ValueError, "local lab scope"):
            load_ctf_target_manifest(manifest)

    def test_ctf_target_manifest_rejects_non_recon_default_intent(self) -> None:
        manifest = {
            "lab_id": "solve-by-default",
            "title": "Solve By Default",
            "platform": "docker",
            "category": "web",
            "difficulty": "foundation",
            "scope": {"network": "lab_solve_default", "assets": ["http://127.0.0.1:3111"]},
            "provisioning": {"mode": "docker", "network": "lab_solve_default"},
            "policy": {"default_intent": "ctf_solve_autonomous_local"},
        }

        with self.assertRaisesRegex(ValueError, "default_intent"):
            load_ctf_target_manifest(manifest)

    def test_ctf_target_manifest_rejects_legacy_profile_labels(self) -> None:
        manifest = {
            "lab_id": "profile-label-target",
            "title": "Profile Label Target",
            "platform": "docker",
            "category": "web",
            "difficulty": "foundation",
            "scope": {"network": "lab_profile_label", "assets": ["http://127.0.0.1:3112"]},
            "provisioning": {"mode": "docker", "network": "lab_profile_label"},
            "allowed_engagement_profiles": ["hack_the_box"],
            "policy": {"default_intent": "recon_only"},
        }

        with self.assertRaisesRegex(ValueError, "allowed_engagement_profiles"):
            load_ctf_target_manifest(manifest)

    def test_ctf_target_manifest_rejects_unsafe_writeup_access_policy(self) -> None:
        manifest = {
            "lab_id": "writeup-leak-target",
            "title": "Writeup Leak Target",
            "platform": "docker",
            "category": "web",
            "difficulty": "foundation",
            "scope": {"network": "lab_writeup_leak", "assets": ["http://127.0.0.1:3113"]},
            "provisioning": {"mode": "docker", "network": "lab_writeup_leak"},
            "closed_book": {"writeup_access_policy": "always"},
            "policy": {"default_intent": "recon_only"},
        }

        with self.assertRaisesRegex(ValueError, "writeup_access_policy"):
            load_ctf_target_manifest(manifest)

    def test_ctf_target_manifest_file_loads_json_through_contract_validation(self) -> None:
        manifest = {
            "lab_id": "json-target",
            "title": "JSON Target",
            "platform": "docker",
            "category": "web",
            "difficulty": "foundation",
            "scope": {"network": "json_lab", "assets": ["http://127.0.0.1:3110"]},
            "provisioning": {"mode": "docker", "network": "json_lab"},
            "closed_book": {"strip_paths": ["writeups/"]},
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "target.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")

            target = load_ctf_target_manifest_file(path)

        self.assertEqual(target.id, "json-target")
        self.assertEqual(target.scope.assets, ("http://127.0.0.1:3110",))
        self.assertEqual(target.closed_book.strip_paths, ("writeups/",))


if __name__ == "__main__":
    unittest.main()
