from __future__ import annotations

from pathlib import Path
import unittest

from primordial.labs.ctf import (
    load_ctf_lab_phase_catalog,
    load_ctf_target_manifest,
    verify_cloudgoat_phase_controls,
    verify_sandbox_cloud_environment,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "catalog" / "labs" / "ctf_lab_phases.yaml"


class CTFHarnessCloudGoatTests(unittest.TestCase):
    def test_cloudgoat_controls_enforce_account_region_and_teardown_evidence(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(7)
        target = _cloudgoat_target()
        environment = verify_sandbox_cloud_environment(
            target,
            account_id="111122223333",
            regions=["us-east-1"],
            observed_assets=["aws-account-111122223333", "us-east-1"],
            evidence_refs=["evidence:cloudgoat-account-boundary", "evidence:cloudgoat-teardown"],
            reset_evidence_ref="evidence:cloudgoat-teardown",
            profile="co_internal_lab",
            observations={"identity": {"account_hash": "sha256:cloudgoat-sandbox"}},
        )

        result = verify_cloudgoat_phase_controls(
            phase,
            target,
            environment_proof=environment,
            account_id="111122223333",
            region="us-east-1",
            scoped_resources=[
                {
                    "id": "cloudgoat-iam-role",
                    "target_id": target.id,
                    "account_id": "111122223333",
                    "region": "us-east-1",
                    "asset": "aws-account-111122223333",
                    "resource_type": "iam_role",
                    "source_refs": ["source:cloudgoat-local-terraform-plan"],
                    "evidence_ids": ["evidence:cloudgoat-account-boundary"],
                }
            ],
            teardown_actions=[
                {
                    "id": "cloudgoat-destroy",
                    "target_id": target.id,
                    "account_id": "111122223333",
                    "region": "us-east-1",
                    "action": "terraform_destroy",
                    "teardown_evidence_ref": "evidence:cloudgoat-teardown",
                    "evidence_ids": ["evidence:cloudgoat-teardown"],
                }
            ],
        )

        self.assertEqual(result.target_id, "cloudgoat-sandbox")
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.account_id, "111122223333")
        self.assertEqual(result.region, "us-east-1")
        self.assertEqual(result.resource_ids, ("cloudgoat-iam-role",))
        self.assertEqual(result.teardown_ids, ("cloudgoat-destroy",))
        self.assertIn("sandbox_cloud_account_verified", result.exit_gates)
        self.assertIn("account_boundary_and_region_scope_enforced", result.exit_gates)
        self.assertIn("teardown_evidence_recorded", result.exit_gates)
        self.assertIn("evidence:cloudgoat-account-boundary", result.evidence_refs)

    def test_cloudgoat_controls_reject_cross_account_resource(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(7)
        target = _cloudgoat_target()
        environment = verify_sandbox_cloud_environment(
            target,
            account_id="111122223333",
            regions=["us-east-1"],
            observed_assets=["aws-account-111122223333", "us-east-1"],
            evidence_refs=["evidence:cloudgoat-account-boundary", "evidence:cloudgoat-teardown"],
            reset_evidence_ref="evidence:cloudgoat-teardown",
            profile="co_internal_lab",
        )

        with self.assertRaisesRegex(ValueError, "account"):
            verify_cloudgoat_phase_controls(
                phase,
                target,
                environment_proof=environment,
                account_id="111122223333",
                region="us-east-1",
                scoped_resources=[
                    {
                        "id": "other-account-role",
                        "target_id": target.id,
                        "account_id": "999988887777",
                        "region": "us-east-1",
                        "asset": "aws-account-111122223333",
                        "resource_type": "iam_role",
                        "source_refs": ["source:cloudgoat-local-terraform-plan"],
                        "evidence_ids": ["evidence:cloudgoat-account-boundary"],
                    }
                ],
                teardown_actions=[
                    {
                        "id": "cloudgoat-destroy",
                        "target_id": target.id,
                        "account_id": "111122223333",
                        "region": "us-east-1",
                        "action": "terraform_destroy",
                        "teardown_evidence_ref": "evidence:cloudgoat-teardown",
                        "evidence_ids": ["evidence:cloudgoat-teardown"],
                    }
                ],
            )

    def test_cloudgoat_controls_reject_unverified_teardown_evidence(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(7)
        target = _cloudgoat_target()
        environment = verify_sandbox_cloud_environment(
            target,
            account_id="111122223333",
            regions=["us-east-1"],
            observed_assets=["aws-account-111122223333", "us-east-1"],
            evidence_refs=["evidence:cloudgoat-account-boundary", "evidence:cloudgoat-teardown"],
            reset_evidence_ref="evidence:cloudgoat-teardown",
            profile="co_internal_lab",
        )

        with self.assertRaisesRegex(ValueError, "teardown_evidence_ref"):
            verify_cloudgoat_phase_controls(
                phase,
                target,
                environment_proof=environment,
                account_id="111122223333",
                region="us-east-1",
                scoped_resources=[
                    {
                        "id": "cloudgoat-iam-role",
                        "target_id": target.id,
                        "account_id": "111122223333",
                        "region": "us-east-1",
                        "asset": "aws-account-111122223333",
                        "resource_type": "iam_role",
                        "source_refs": ["source:cloudgoat-local-terraform-plan"],
                        "evidence_ids": ["evidence:cloudgoat-account-boundary"],
                    }
                ],
                teardown_actions=[
                    {
                        "id": "cloudgoat-destroy",
                        "target_id": target.id,
                        "account_id": "111122223333",
                        "region": "us-east-1",
                        "action": "terraform_destroy",
                        "teardown_evidence_ref": "evidence:unknown-teardown",
                        "evidence_ids": ["evidence:cloudgoat-teardown"],
                    }
                ],
            )


def _cloudgoat_target():
    return load_ctf_target_manifest(
        {
            "lab_id": "cloudgoat-sandbox",
            "title": "CloudGoat Sandbox Lab",
            "platform": "cloud",
            "category": "cloud",
            "difficulty": "advanced",
            "target_family": "cloudgoat",
            "source": {
                "repo_url": "https://github.com/RhinoSecurityLabs/cloudgoat",
                "path": "scenarios",
            },
            "scope": {
                "network": "aws-sandbox-111122223333",
                "assets": ["aws-account-111122223333", "us-east-1"],
            },
            "provisioning": {
                "mode": "sandbox_cloud",
                "network": "aws-sandbox-111122223333",
            },
            "evidence": {"required": ["account_identity", "region_scope", "teardown_evidence"]},
            "policy": {"default_intent": "recon_only"},
        }
    )


if __name__ == "__main__":
    unittest.main()
