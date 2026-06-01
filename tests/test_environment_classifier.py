from __future__ import annotations

import unittest
from pathlib import Path

from primordial.core.environment import EnvironmentClassifier


REPO_ROOT = Path(__file__).resolve().parents[1]


class EnvironmentClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.classifier = EnvironmentClassifier.from_goal_file(REPO_ROOT / "goal" / "fragments" / "environments.yaml")

    def test_profile_label_alone_does_not_upgrade_operator_intent(self) -> None:
        classification = self.classifier.classify(profile="hack_the_box")

        self.assertEqual(classification.environment, "real_world")
        self.assertEqual(classification.default_intent, "recon_only")
        self.assertFalse(classification.upgrade_applied)
        self.assertEqual(classification.reason, "environment_proof_required")

    def test_verified_platform_lab_proof_allows_htb_default_intent(self) -> None:
        classification = self.classifier.classify(
            profile="hack_the_box",
            payload={
                "metadata": {
                    "environment_class": "platform_lab",
                    "environment_verified": True,
                }
            },
        )

        self.assertEqual(classification.environment, "platform_lab")
        self.assertEqual(classification.default_intent, "htb_lab")
        self.assertTrue(classification.verified_lab)
        self.assertTrue(classification.upgrade_applied)
        self.assertIn("scope_payload.metadata", classification.proof_sources)

    def test_local_ctf_manifest_shape_proves_local_container_environment(self) -> None:
        classification = self.classifier.classify(
            profile="co_internal_lab",
            payload={
                "lab_id": "training-juice-shop",
                "provisioning": {"mode": "docker"},
                "scope": {"assets": ["http://127.0.0.1:3000"]},
            },
        )

        self.assertEqual(classification.environment, "local_ctf_container")
        self.assertEqual(classification.default_intent, "local_ctf_container")
        self.assertTrue(classification.verified_lab)
        self.assertTrue(classification.upgrade_applied)


if __name__ == "__main__":
    unittest.main()
