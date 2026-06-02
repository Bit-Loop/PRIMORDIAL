from __future__ import annotations

import json
import unittest

from primordial.labs.ctf import (
    probe_benchmark_environment,
    probe_local_ad_lab_environment,
    probe_local_cluster_environment,
    probe_localstack_cloud_environment,
    load_ctf_target_manifest,
)
from tests.support import fixture_flag


class CTFHarnessLiveLabProbeTests(unittest.TestCase):
    def test_local_cluster_probe_hashes_kubectl_output_and_verifies_namespace(self) -> None:
        target = load_ctf_target_manifest(
            {
                "lab_id": "kubernetes-goat-local",
                "title": "Kubernetes Goat Local Lab",
                "platform": "kubernetes",
                "category": "kubernetes",
                "difficulty": "advanced",
                "target_family": "kubernetes_goat",
                "scope": {"network": "kind-primordial-k8s", "assets": ["http://127.0.0.1:30080"]},
                "provisioning": {"mode": "kind", "network": "kind-primordial-k8s"},
                "policy": {"default_intent": "recon_only"},
            }
        )
        proof = probe_local_cluster_environment(
            target,
            namespace="kg-local",
            reset_evidence_ref="evidence:kubernetes-reset",
            profile="co_internal_lab",
            command_runner=_runner(stdout="kubectl observed " + fixture_flag()),
        )

        payload = json.dumps(proof.as_payload(), sort_keys=True)
        self.assertEqual(proof.environment_kind, "local_cluster")
        self.assertEqual(proof.provisioning["namespace"], "kg-local")
        self.assertIn("local_cluster_environment_verified", proof.exit_gates)
        self.assertIn("evidence:kubernetes-reset", proof.evidence_refs)
        self.assertNotIn(fixture_flag(), payload)
        self.assertIn("stdout_sha256", payload)

    def test_local_ad_probe_verifies_libvirt_network_and_domain_assets(self) -> None:
        target = load_ctf_target_manifest(
            {
                "lab_id": "goad-light-local",
                "title": "GOAD-Light Local Lab",
                "platform": "goad_light",
                "category": "active_directory",
                "difficulty": "advanced",
                "target_family": "goad_light",
                "scope": {"network": "goad.local", "assets": ["dc1.goad.local", "dc2.goad.local"]},
                "provisioning": {"mode": "goad_light", "network": "goad.local"},
                "policy": {"default_intent": "recon_only"},
            }
        )

        proof = probe_local_ad_lab_environment(
            target,
            domain="goad.local",
            reset_evidence_ref="evidence:goad-reset",
            profile="co_internal_lab",
            command_runner=_runner(stdout="virsh and nmap observed domain controllers"),
        )

        self.assertEqual(proof.environment_kind, "local_ad_lab")
        self.assertEqual(proof.provisioning["domain"], "goad.local")
        self.assertIn("local_ad_lab_environment_verified", proof.exit_gates)
        self.assertIn("evidence:goad-reset", proof.evidence_refs)

    def test_localstack_probe_verifies_local_cloud_account_without_external_cloud(self) -> None:
        target = load_ctf_target_manifest(
            {
                "lab_id": "cloudgoat-localstack",
                "title": "CloudGoat LocalStack Lab",
                "platform": "terraform",
                "category": "cloud",
                "difficulty": "advanced",
                "target_family": "cloudgoat",
                "scope": {"network": "localstack-account-123456789012", "assets": ["us-east-1"]},
                "provisioning": {"mode": "terraform", "network": "localstack-account-123456789012"},
                "policy": {"default_intent": "recon_only"},
            }
        )

        proof = probe_localstack_cloud_environment(
            target,
            account_id="123456789012",
            regions=["us-east-1"],
            reset_evidence_ref="evidence:localstack-teardown",
            profile="co_internal_lab",
            endpoint_url="http://127.0.0.1:4566",
            command_runner=_runner(stdout='{"Account":"123456789012"}'),
        )

        self.assertEqual(proof.environment_kind, "sandbox_cloud_account")
        self.assertEqual(proof.provisioning["account_id"], "123456789012")
        self.assertEqual(proof.provisioning["regions"], ["us-east-1"])
        self.assertIn("sandbox_cloud_account_verified", proof.exit_gates)
        self.assertIn("evidence:localstack-teardown", proof.evidence_refs)

    def test_benchmark_probe_verifies_rotation_and_hashes_target_observations(self) -> None:
        target = load_ctf_target_manifest(
            {
                "lab_id": "nyu-ctf-bench-local",
                "title": "NYU CTF Bench Local Rotation",
                "platform": "benchmark",
                "category": "benchmark",
                "difficulty": "advanced",
                "target_family": "nyu_ctf_bench",
                "scope": {
                    "network": "local-benchmark-rotation",
                    "assets": ["http://127.0.0.1:4101", "http://127.0.0.1:4102"],
                },
                "provisioning": {"mode": "benchmark", "network": "local-benchmark-rotation"},
                "policy": {"default_intent": "recon_only"},
            }
        )

        proof = probe_benchmark_environment(
            target,
            reset_evidence_ref="evidence:benchmark-reset",
            profile="co_internal_lab",
            command_runner=_runner(stdout="benchmark target observed"),
        )

        self.assertEqual(proof.environment_kind, "benchmark_environment")
        self.assertEqual(proof.provisioning["target_rotation"], list(target.scope.assets))
        self.assertIn("benchmark_environment_verified", proof.exit_gates)
        self.assertIn("evidence:benchmark-reset", proof.evidence_refs)

    def test_live_probe_rejects_failed_local_command(self) -> None:
        target = load_ctf_target_manifest(
            {
                "lab_id": "kubernetes-goat-local",
                "title": "Kubernetes Goat Local Lab",
                "platform": "kubernetes",
                "category": "kubernetes",
                "difficulty": "advanced",
                "target_family": "kubernetes_goat",
                "scope": {"network": "kind-primordial-k8s", "assets": ["http://127.0.0.1:30080"]},
                "provisioning": {"mode": "kind", "network": "kind-primordial-k8s"},
                "policy": {"default_intent": "recon_only"},
            }
        )

        with self.assertRaisesRegex(ValueError, "live probe command failed"):
            probe_local_cluster_environment(
                target,
                namespace="kg-local",
                reset_evidence_ref="evidence:kubernetes-reset",
                profile="co_internal_lab",
                command_runner=_runner(returncode=1, stderr="missing namespace"),
            )


def _runner(*, stdout: str = "", stderr: str = "", returncode: int = 0):
    def run(command: tuple[str, ...]) -> dict[str, object]:
        return {
            "command": list(command),
            "returncode": returncode,
            "stdout": stdout,
            "stderr": stderr,
        }

    return run


if __name__ == "__main__":
    unittest.main()
