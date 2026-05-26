from __future__ import annotations

import unittest

from primordial.labs.ctf import ClosedBookPackage, load_ctf_target_manifest


class ClosedBookPackageContractTests(unittest.TestCase):
    def test_closed_book_package_strips_solution_writeup_and_hidden_material(self) -> None:
        target = load_ctf_target_manifest(
            {
                "lab_id": "juice-shop-foundation",
                "title": "Juice Shop Foundation",
                "platform": "docker",
                "category": "web",
                "difficulty": "foundation",
                "scope": {"network": "lab_js_foundation", "assets": ["127.0.0.1:3100"]},
                "provisioning": {"mode": "docker", "network": "lab_js_foundation"},
                "closed_book": {
                    "strip_paths": [
                        "docs/",
                        "solutions/",
                        "writeups/",
                        "companion-guide/",
                    ]
                },
            }
        )

        package = ClosedBookPackage.build(
            target=target,
            candidate_paths=[
                "compose.yaml",
                "src/server.js",
                "docs/setup.md",
                "solutions/admin-bypass.md",
                "writeups/juice-shop-foundation.md",
                "companion-guide/chapter-1.md",
                "fixtures/expected_flags.json",
                "exports/generated-postmortem.md",
                "traces/prior-solve.json",
            ],
        )

        self.assertEqual(package.target_id, "juice-shop-foundation")
        self.assertEqual(package.agent_paths, ("compose.yaml", "src/server.js"))
        self.assertIn("solutions/admin-bypass.md", package.operator_only_paths)
        self.assertIn("fixtures/expected_flags.json", package.operator_only_paths)
        self.assertIn("exports/generated-postmortem.md", package.operator_only_paths)
        self.assertIn("traces/prior-solve.json", package.operator_only_paths)

    def test_closed_book_package_rejects_agent_paths_with_raw_flag_material(self) -> None:
        target = load_ctf_target_manifest(
            {
                "lab_id": "ctf-package",
                "title": "CTF Package",
                "platform": "docker",
                "category": "web",
                "difficulty": "foundation",
            }
        )

        with self.assertRaisesRegex(ValueError, "raw flag"):
            ClosedBookPackage.build(
                target=target,
                candidate_paths=["src/ctf{hidden-answer}.txt"],
            )


if __name__ == "__main__":
    unittest.main()
