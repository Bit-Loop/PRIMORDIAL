from __future__ import annotations

import unittest

from primordial.labs.ctf import FakeCTFdClient, load_ctf_target_manifest
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

    def test_fake_ctfd_client_submission_requires_captured_flag_evidence_ref(self) -> None:
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

        with self.assertRaisesRegex(ValueError, "captured_flag_ref"):
            client.submit_flag(
                challenge_id="juice-shop-foundation",
                captured_flag_ref="secret_ref:captured-flag-redacted",
                active_intent="ctf_solve_assisted",
            )

    def test_fake_ctfd_client_records_evidence_backed_submission(self) -> None:
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

        updated = client.submit_flag(
            challenge_id="juice-shop-foundation",
            captured_flag_ref="evidence:captured-flag-redacted",
            active_intent="ctf_solve_assisted",
        )

        self.assertEqual(updated.submissions[0]["captured_flag_ref"], "evidence:captured-flag-redacted")

    def test_fake_ctfd_client_loads_closed_book_export_without_flags(self) -> None:
        target = _juice_shop_target()

        client = FakeCTFdClient.from_closed_book_export(
            {
                "challenges": [
                    {
                        "id": "juice-shop-foundation",
                        "name": "Juice Shop Foundation",
                        "category": "web",
                        "value": 100,
                        "tags": [{"value": "web"}, {"name": "juice-shop"}],
                        "connection_info": "http://127.0.0.1:3100",
                    }
                ],
                "scoreboard": {"juice-shop-foundation": {"solved": False, "value": 100}},
            },
            target=target,
        )

        challenge = client.get_challenge("juice-shop-foundation")
        self.assertEqual(challenge["title"], "Juice Shop Foundation")
        self.assertEqual(challenge["target_url"], "http://127.0.0.1:3100")
        self.assertEqual(challenge["tags"], ("web", "juice-shop"))
        self.assertEqual(client.get_scoreboard("juice-shop-foundation")["value"], 100)

    def test_fake_ctfd_client_rejects_closed_book_export_with_flags(self) -> None:
        with self.assertRaisesRegex(ValueError, "hidden flag"):
            FakeCTFdClient.from_closed_book_export(
                {
                    "challenges": [
                        {
                            "id": "juice-shop-foundation",
                            "name": "Juice Shop Foundation",
                            "category": "web",
                            "value": 100,
                            "flags": [{"content": fixture_flag("hidden-answer")}],
                        }
                    ],
                    "scoreboard": {},
                },
                target=_juice_shop_target(),
            )

    def test_fake_ctfd_client_rejects_closed_book_export_target_mismatch(self) -> None:
        with self.assertRaisesRegex(ValueError, "challenge_id"):
            FakeCTFdClient.from_closed_book_export(
                {
                    "challenges": [
                        {
                            "id": "other-target",
                            "name": "Other Target",
                            "category": "web",
                            "value": 100,
                            "connection_info": "http://127.0.0.1:3100",
                        }
                    ],
                    "scoreboard": {},
                },
                target=_juice_shop_target(),
            )

    def test_fake_ctfd_client_rejects_closed_book_export_outside_target_scope(self) -> None:
        with self.assertRaisesRegex(ValueError, "target scope"):
            FakeCTFdClient.from_closed_book_export(
                {
                    "challenges": [
                        {
                            "id": "juice-shop-foundation",
                            "name": "Juice Shop Foundation",
                            "category": "web",
                            "value": 100,
                            "connection_info": "http://127.0.0.1:3999",
                        }
                    ],
                    "scoreboard": {},
                },
                target=_juice_shop_target(),
            )


def _juice_shop_target():
    return load_ctf_target_manifest(
        {
            "lab_id": "juice-shop-foundation",
            "title": "OWASP Juice Shop Foundation",
            "platform": "docker",
            "category": "web",
            "difficulty": "foundation",
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
            "evidence": {"required": ["http_request", "http_response"]},
            "policy": {"default_intent": "recon_only"},
        }
    )


if __name__ == "__main__":
    unittest.main()
