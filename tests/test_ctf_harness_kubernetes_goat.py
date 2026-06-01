from __future__ import annotations

from pathlib import Path
import unittest

from primordial.labs.ctf import (
    load_ctf_lab_phase_catalog,
    load_ctf_target_manifest,
    verify_kubernetes_goat_phase_controls,
    verify_local_cluster_environment,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "catalog" / "labs" / "ctf_lab_phases.yaml"


class CTFHarnessKubernetesGoatTests(unittest.TestCase):
    def test_kubernetes_goat_controls_bind_resources_and_resets_to_namespace(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(5)
        target = _kubernetes_goat_target()
        environment = verify_local_cluster_environment(
            target,
            namespace="kg-local",
            observed_assets=["http://127.0.0.1:30080"],
            evidence_refs=["evidence:kubernetes-goat-health", "evidence:kubernetes-goat-reset-teardown"],
            reset_evidence_ref="evidence:kubernetes-goat-reset-teardown",
            profile="co_internal_lab",
            observations={"cluster": {"provider": "kind", "context": "kind-primordial-k8s"}},
        )

        result = verify_kubernetes_goat_phase_controls(
            phase,
            target,
            environment_proof=environment,
            namespace="kg-local",
            scoped_resources=[
                {
                    "id": "kg-web-service",
                    "target_id": target.id,
                    "namespace": "kg-local",
                    "kind": "service",
                    "name": "kubernetes-goat-home",
                    "asset": "http://127.0.0.1:30080",
                    "source_refs": ["source:kubernetes-goat-local-manifests"],
                    "evidence_ids": ["evidence:kubernetes-goat-health"],
                }
            ],
            mutation_resets=[
                {
                    "id": "kg-local-reset",
                    "target_id": target.id,
                    "namespace": "kg-local",
                    "action": "delete_namespace_and_reapply",
                    "reset_evidence_ref": "evidence:kubernetes-goat-reset-teardown",
                    "evidence_ids": ["evidence:kubernetes-goat-reset-teardown"],
                }
            ],
        )

        self.assertEqual(result.target_id, "kubernetes-goat-local")
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.namespace, "kg-local")
        self.assertEqual(result.resource_ids, ("kg-web-service",))
        self.assertEqual(result.reset_ids, ("kg-local-reset",))
        self.assertIn("namespace_scope_enforced", result.exit_gates)
        self.assertIn("cluster_mutations_reset_between_runs", result.exit_gates)
        self.assertIn("evidence:kubernetes-goat-health", result.evidence_refs)

    def test_kubernetes_goat_controls_reject_resources_outside_namespace(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(5)
        target = _kubernetes_goat_target()
        environment = verify_local_cluster_environment(
            target,
            namespace="kg-local",
            observed_assets=["http://127.0.0.1:30080"],
            evidence_refs=["evidence:kubernetes-goat-health", "evidence:kubernetes-goat-reset-teardown"],
            reset_evidence_ref="evidence:kubernetes-goat-reset-teardown",
            profile="co_internal_lab",
        )

        with self.assertRaisesRegex(ValueError, "namespace"):
            verify_kubernetes_goat_phase_controls(
                phase,
                target,
                environment_proof=environment,
                namespace="kg-local",
                scoped_resources=[
                    {
                        "id": "default-service",
                        "target_id": target.id,
                        "namespace": "default",
                        "kind": "service",
                        "name": "kubernetes-goat-home",
                        "asset": "http://127.0.0.1:30080",
                        "source_refs": ["source:kubernetes-goat-local-manifests"],
                        "evidence_ids": ["evidence:kubernetes-goat-health"],
                    }
                ],
                mutation_resets=[
                    {
                        "id": "kg-local-reset",
                        "target_id": target.id,
                        "namespace": "kg-local",
                        "action": "delete_namespace_and_reapply",
                        "reset_evidence_ref": "evidence:kubernetes-goat-reset-teardown",
                        "evidence_ids": ["evidence:kubernetes-goat-reset-teardown"],
                    }
                ],
            )

    def test_kubernetes_goat_controls_reject_unverified_reset_evidence(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(5)
        target = _kubernetes_goat_target()
        environment = verify_local_cluster_environment(
            target,
            namespace="kg-local",
            observed_assets=["http://127.0.0.1:30080"],
            evidence_refs=["evidence:kubernetes-goat-health", "evidence:kubernetes-goat-reset-teardown"],
            reset_evidence_ref="evidence:kubernetes-goat-reset-teardown",
            profile="co_internal_lab",
        )

        with self.assertRaisesRegex(ValueError, "reset_evidence_ref"):
            verify_kubernetes_goat_phase_controls(
                phase,
                target,
                environment_proof=environment,
                namespace="kg-local",
                scoped_resources=[
                    {
                        "id": "kg-web-service",
                        "target_id": target.id,
                        "namespace": "kg-local",
                        "kind": "service",
                        "name": "kubernetes-goat-home",
                        "asset": "http://127.0.0.1:30080",
                        "source_refs": ["source:kubernetes-goat-local-manifests"],
                        "evidence_ids": ["evidence:kubernetes-goat-health"],
                    }
                ],
                mutation_resets=[
                    {
                        "id": "unverified-reset",
                        "target_id": target.id,
                        "namespace": "kg-local",
                        "action": "delete_namespace_and_reapply",
                        "reset_evidence_ref": "evidence:unknown-reset",
                        "evidence_ids": ["evidence:kubernetes-goat-reset-teardown"],
                    }
                ],
            )


def _kubernetes_goat_target():
    return load_ctf_target_manifest(
        {
            "lab_id": "kubernetes-goat-local",
            "title": "Kubernetes Goat Local Lab",
            "platform": "kubernetes",
            "category": "kubernetes",
            "difficulty": "advanced",
            "target_family": "kubernetes_goat",
            "source": {
                "repo_url": "https://github.com/madhuakula/kubernetes-goat",
                "path": "scenarios",
            },
            "scope": {
                "network": "kind-primordial-k8s",
                "assets": ["http://127.0.0.1:30080"],
            },
            "provisioning": {
                "mode": "kind",
                "network": "kind-primordial-k8s",
                "published_ports": [{"host": 30080, "container": 80}],
            },
            "evidence": {"required": ["cluster_context", "namespace_inventory", "reset_teardown"]},
            "policy": {"default_intent": "recon_only"},
        }
    )


if __name__ == "__main__":
    unittest.main()
