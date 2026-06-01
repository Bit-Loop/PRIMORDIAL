from __future__ import annotations

from pathlib import Path
import unittest

from primordial.labs.ctf import (
    load_ctf_lab_phase_catalog,
    load_ctf_target_manifest,
    verify_cicd_goat_phase_controls,
    verify_local_container_environment,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "catalog" / "labs" / "ctf_lab_phases.yaml"


class CTFHarnessCICDGoatTests(unittest.TestCase):
    def test_cicd_goat_controls_bind_attack_paths_and_mutations_to_verified_lab(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(4)
        target = _cicd_goat_target()
        environment = verify_local_container_environment(
            target,
            observed_assets=["http://127.0.0.1:4111", "http://127.0.0.1:4180"],
            evidence_refs=["evidence:cicd-goat-health", "evidence:cicd-goat-reset-teardown"],
            reset_evidence_ref="evidence:cicd-goat-reset-teardown",
            profile="co_internal_lab",
        )

        result = verify_cicd_goat_phase_controls(
            phase,
            target,
            environment_proof=environment,
            attack_paths=[
                {
                    "id": "cicd-goat-jenkins-path",
                    "target_id": target.id,
                    "asset": "http://127.0.0.1:4111",
                    "ci_system": "jenkins",
                    "source_refs": ["source:cicd-goat-local-compose"],
                    "evidence_ids": ["evidence:cicd-goat-health"],
                }
            ],
            pipeline_actions=[
                {
                    "id": "local-job-trigger-review",
                    "target_id": target.id,
                    "asset": "http://127.0.0.1:4111",
                    "action": "trigger_pipeline",
                    "scope": "local_lab",
                    "environment_ref": "evidence:cicd-goat-health",
                    "evidence_ids": ["evidence:cicd-goat-health"],
                }
            ],
        )

        self.assertEqual(result.target_id, "cicd-goat-local")
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.attack_path_ids, ("cicd-goat-jenkins-path",))
        self.assertEqual(result.pipeline_action_ids, ("local-job-trigger-review",))
        self.assertIn("ci_cd_attack_paths_bound_to_lab_scope", result.exit_gates)
        self.assertIn("no_external_pipeline_mutation_without_verified_lab", result.exit_gates)
        self.assertIn("evidence:cicd-goat-health", result.evidence_refs)

    def test_cicd_goat_controls_reject_public_pipeline_mutation(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(4)
        target = _cicd_goat_target()
        environment = verify_local_container_environment(
            target,
            observed_assets=["http://127.0.0.1:4111", "http://127.0.0.1:4180"],
            evidence_refs=["evidence:cicd-goat-health", "evidence:cicd-goat-reset-teardown"],
            reset_evidence_ref="evidence:cicd-goat-reset-teardown",
            profile="co_internal_lab",
        )

        with self.assertRaisesRegex(ValueError, "local_lab"):
            verify_cicd_goat_phase_controls(
                phase,
                target,
                environment_proof=environment,
                attack_paths=[
                    {
                        "id": "cicd-goat-jenkins-path",
                        "target_id": target.id,
                        "asset": "http://127.0.0.1:4111",
                        "ci_system": "jenkins",
                        "source_refs": ["source:cicd-goat-local-compose"],
                        "evidence_ids": ["evidence:cicd-goat-health"],
                    }
                ],
                pipeline_actions=[
                    {
                        "id": "external-repo-trigger",
                        "target_id": target.id,
                        "asset": "http://127.0.0.1:4111",
                        "action": "trigger_pipeline",
                        "scope": "public_repo",
                        "environment_ref": "evidence:cicd-goat-health",
                        "evidence_ids": ["evidence:cicd-goat-health"],
                    }
                ],
            )

    def test_cicd_goat_controls_reject_attack_paths_outside_lab_scope(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(4)
        target = _cicd_goat_target()
        environment = verify_local_container_environment(
            target,
            observed_assets=["http://127.0.0.1:4111", "http://127.0.0.1:4180"],
            evidence_refs=["evidence:cicd-goat-health", "evidence:cicd-goat-reset-teardown"],
            reset_evidence_ref="evidence:cicd-goat-reset-teardown",
            profile="co_internal_lab",
        )

        with self.assertRaisesRegex(ValueError, "lab scope"):
            verify_cicd_goat_phase_controls(
                phase,
                target,
                environment_proof=environment,
                attack_paths=[
                    {
                        "id": "external-path",
                        "target_id": target.id,
                        "asset": "https://ci.example.com",
                        "ci_system": "jenkins",
                        "source_refs": ["source:cicd-goat-local-compose"],
                        "evidence_ids": ["evidence:cicd-goat-health"],
                    }
                ],
                pipeline_actions=[
                    {
                        "id": "local-job-trigger-review",
                        "target_id": target.id,
                        "asset": "http://127.0.0.1:4111",
                        "action": "trigger_pipeline",
                        "scope": "local_lab",
                        "environment_ref": "evidence:cicd-goat-health",
                        "evidence_ids": ["evidence:cicd-goat-health"],
                    }
                ],
            )


def _cicd_goat_target():
    return load_ctf_target_manifest(
        {
            "lab_id": "cicd-goat-local",
            "title": "CI/CD Goat Local Lab",
            "platform": "docker",
            "category": "ci_cd",
            "difficulty": "intermediate",
            "target_family": "ci_cd_goat",
            "source": {
                "repo_url": "https://github.com/cider-security-research/cicd-goat",
                "path": "docker-compose.yaml",
            },
            "scope": {
                "network": "lab_cicd_goat",
                "assets": ["http://127.0.0.1:4111", "http://127.0.0.1:4180"],
            },
            "provisioning": {
                "mode": "docker",
                "compose_project": "cicd_goat",
                "network": "lab_cicd_goat",
                "published_ports": [{"host": 4111, "container": 8080}, {"host": 4180, "container": 80}],
            },
            "evidence": {"required": ["http_request", "http_response", "pipeline_action"]},
            "policy": {"default_intent": "recon_only"},
        }
    )


if __name__ == "__main__":
    unittest.main()
