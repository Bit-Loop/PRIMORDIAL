from __future__ import annotations

import unittest

from primordial.labs.ctf import load_ctf_target_manifest, verify_local_container_environment
from tests.support import fixture_flag


class CTFHarnessEnvironmentProofTests(unittest.TestCase):
    def test_local_container_environment_proof_records_phase_gate_and_evidence(self) -> None:
        target = _juice_shop_target()

        proof = verify_local_container_environment(
            target,
            observed_assets=["http://127.0.0.1:3100"],
            evidence_refs=["evidence:container-health", "evidence:reset-ready"],
            reset_evidence_ref="evidence:reset-ready",
            profile="co_internal_lab",
        )

        self.assertEqual(proof.target_id, "juice-shop-foundation")
        self.assertEqual(proof.status, "verified")
        self.assertEqual(proof.profile, "co_internal_lab")
        self.assertEqual(proof.environment_kind, "local_container")
        self.assertEqual(proof.observed_assets, ("http://127.0.0.1:3100",))
        self.assertEqual(proof.evidence_refs, ("evidence:container-health", "evidence:reset-ready"))
        self.assertEqual(proof.reset_evidence_ref, "evidence:reset-ready")
        self.assertEqual(proof.exit_gates, ("local_container_environment_verified",))
        self.assertEqual(
            proof.as_payload()["provisioning"],
            {
                "mode": "docker",
                "network": "lab_js_foundation",
                "compose_project": "js_foundation",
                "published_ports": [{"host": 3100, "container": 3000}],
            },
        )

    def test_local_container_environment_proof_requires_all_target_assets_observed(self) -> None:
        target = _juice_shop_target()

        with self.assertRaisesRegex(ValueError, "observed_assets"):
            verify_local_container_environment(
                target,
                observed_assets=["http://127.0.0.1:3999"],
                evidence_refs=["evidence:container-health", "evidence:reset-ready"],
                reset_evidence_ref="evidence:reset-ready",
                profile="co_internal_lab",
            )

    def test_local_container_environment_proof_requires_evidence_refs(self) -> None:
        target = _juice_shop_target()

        with self.assertRaisesRegex(ValueError, "evidence:<id>"):
            verify_local_container_environment(
                target,
                observed_assets=["http://127.0.0.1:3100"],
                evidence_refs=["note:container-health", "evidence:reset-ready"],
                reset_evidence_ref="evidence:reset-ready",
                profile="co_internal_lab",
            )

    def test_local_container_environment_proof_requires_reset_evidence_in_evidence_refs(self) -> None:
        target = _juice_shop_target()

        with self.assertRaisesRegex(ValueError, "reset_evidence_ref"):
            verify_local_container_environment(
                target,
                observed_assets=["http://127.0.0.1:3100"],
                evidence_refs=["evidence:container-health"],
                reset_evidence_ref="evidence:reset-ready",
                profile="co_internal_lab",
            )

    def test_local_container_environment_proof_rejects_non_container_targets(self) -> None:
        target = load_ctf_target_manifest(
            {
                "lab_id": "manual-web-lab",
                "title": "Manual Web Lab",
                "platform": "manual",
                "category": "web",
                "difficulty": "foundation",
                "scope": {"network": "manual_lab", "assets": ["http://127.0.0.1:3101"]},
                "provisioning": {"mode": "manual", "network": "manual_lab"},
                "policy": {"default_intent": "recon_only"},
            }
        )

        with self.assertRaisesRegex(ValueError, "local container"):
            verify_local_container_environment(
                target,
                observed_assets=["http://127.0.0.1:3101"],
                evidence_refs=["evidence:container-health", "evidence:reset-ready"],
                reset_evidence_ref="evidence:reset-ready",
                profile="co_internal_lab",
            )

    def test_local_container_environment_proof_rejects_hidden_material(self) -> None:
        target = _juice_shop_target()

        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            verify_local_container_environment(
                target,
                observed_assets=["http://127.0.0.1:3100"],
                evidence_refs=["evidence:container-health", "evidence:reset-ready"],
                reset_evidence_ref="evidence:reset-ready",
                profile="co_internal_lab",
                observations={"banner": fixture_flag()},
            )


def _juice_shop_target():
    return load_ctf_target_manifest(
        {
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
    )


if __name__ == "__main__":
    unittest.main()
