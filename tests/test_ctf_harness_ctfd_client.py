from __future__ import annotations

import unittest

from primordial.labs.ctf import FakeCTFdClient
from tests.support import fixture_flag


class FakeCTFdClientContractTests(unittest.TestCase):
    def test_fake_ctfd_client_exposes_challenge_and_scoreboard_metadata_only(self) -> None:
        client = FakeCTFdClient.from_records(
            challenges=[
                {
                    "id": "juice-shop-foundation",
                    "title": "Juice Shop Foundation",
                    "category": "web",
                    "value": 100,
                    "tags": ["web", "api"],
                    "target_url": "http://127.0.0.1:3100",
                }
            ],
            scoreboard={"juice-shop-foundation": {"solved": False, "value": 100}},
        )

        challenge = client.get_challenge("juice-shop-foundation")
        scoreboard = client.get_scoreboard("juice-shop-foundation")

        self.assertEqual(challenge["title"], "Juice Shop Foundation")
        self.assertEqual(challenge["tags"], ("web", "api"))
        self.assertNotIn("expected_flag", challenge)
        self.assertEqual(scoreboard["solved"], False)
        self.assertEqual(scoreboard["challenge_id"], "juice-shop-foundation")

    def test_fake_ctfd_client_rejects_hidden_flag_material(self) -> None:
        with self.assertRaisesRegex(ValueError, "hidden flag"):
            FakeCTFdClient.from_records(
                challenges=[
                    {
                        "id": "hidden-answer",
                        "title": "Hidden Answer",
                        "category": "web",
                        "expected_flag": fixture_flag("hidden-answer"),
                    }
                ],
                scoreboard={},
            )

    def test_fake_ctfd_client_rejects_display_hidden_flag_keys(self) -> None:
        with self.assertRaisesRegex(ValueError, "Expected Flag"):
            FakeCTFdClient.from_records(
                challenges=[
                    {
                        "id": "display-hidden-answer",
                        "title": "Display Hidden Answer",
                        "category": "web",
                        "Expected Flag": "redacted-hidden-answer",
                    }
                ],
                scoreboard={},
            )

    def test_fake_ctfd_client_blocks_submission_under_recon_only(self) -> None:
        client = FakeCTFdClient.from_records(
            challenges=[
                {
                    "id": "juice-shop-foundation",
                    "title": "Juice Shop Foundation",
                    "category": "web",
                    "value": 100,
                }
            ],
            scoreboard={},
        )

        with self.assertRaisesRegex(ValueError, "active intent"):
            client.submit_flag(
                challenge_id="juice-shop-foundation",
                captured_flag_ref="evidence:captured-flag-redacted",
                active_intent="recon_only",
            )


if __name__ == "__main__":
    unittest.main()
