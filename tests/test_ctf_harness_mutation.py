from __future__ import annotations

import unittest

from primordial.labs.ctf import MutationPlanner, load_ctf_target_manifest


class MutationPlannerContractTests(unittest.TestCase):
    def test_mutation_planner_is_deterministic_and_preserves_semantic_target_identity(self) -> None:
        target = load_ctf_target_manifest(
            {
                "lab_id": "juice-shop-foundation",
                "title": "Juice Shop Foundation",
                "platform": "docker",
                "category": "web",
                "difficulty": "foundation",
                "scope": {"network": "lab_js_foundation", "assets": ["http://127.0.0.1:3100"]},
                "provisioning": {
                    "mode": "docker",
                    "network": "lab_js_foundation",
                    "published_ports": [{"host": 3100, "container": 3000}],
                },
                "ctfd": {"challenge_id": "juice-shop-foundation"},
                "mutation": {
                    "enabled": True,
                    "mutate": ["target_name", "hostname", "service_ports", "banner_tokens"],
                },
            }
        )

        first = MutationPlanner.plan(target=target, seed="seed-a")
        second = MutationPlanner.plan(target=target, seed="seed-a")
        different = MutationPlanner.plan(target=target, seed="seed-b")

        self.assertEqual(first, second)
        self.assertNotEqual(first.mutated_name, target.name)
        self.assertNotEqual(first.hostname, "juice-shop-foundation")
        self.assertNotEqual(first.published_ports[0]["host"], 3100)
        self.assertIn("banner_token", first.mutations)
        self.assertEqual(first.original_target_id, "juice-shop-foundation")
        self.assertEqual(first.semantic_target_id, "juice-shop-foundation")
        self.assertNotEqual(first.mutated_name, different.mutated_name)

    def test_mutation_planner_does_not_emit_flag_material(self) -> None:
        target = load_ctf_target_manifest(
            {
                "lab_id": "ctf-package",
                "title": "CTF Package",
                "platform": "docker",
                "category": "web",
                "difficulty": "foundation",
                "mutation": {"enabled": True, "mutate": ["target_name", "banner_tokens"]},
            }
        )

        plan = MutationPlanner.plan(target=target, seed="seed-a")
        rendered = repr(plan)

        self.assertNotIn("flag{", rendered.lower())
        self.assertNotIn("ctf{", rendered.lower())


if __name__ == "__main__":
    unittest.main()
