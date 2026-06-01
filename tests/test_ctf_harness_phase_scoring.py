from __future__ import annotations

import unittest

from primordial.labs.ctf import validate_scoring_results_evidence_refs
from tests.support import fixture_flag


class CTFPhaseScoringEvidenceTests(unittest.TestCase):
    def test_scoring_evidence_validator_accepts_target_covered_evidence_refs(self) -> None:
        result = validate_scoring_results_evidence_refs(
            [
                {
                    "target_id": "mbptl-web-cache",
                    "solve_status": "solved",
                    "result": "solved",
                    "evidence_ids": ["evidence:http-proof", "evidence:scoreboard-proof"],
                },
                {
                    "target_id": "mbptl-sql-auth",
                    "solve_status": "review_required",
                    "result": "review",
                    "evidence_ids": ["evidence:review-proof"],
                },
            ],
            target_ids=["mbptl-web-cache", "mbptl-sql-auth"],
        )

        self.assertEqual(result.target_ids, ("mbptl-web-cache", "mbptl-sql-auth"))
        self.assertEqual(
            result.evidence_refs,
            ("evidence:http-proof", "evidence:scoreboard-proof", "evidence:review-proof"),
        )
        self.assertEqual(result.scoring_summary["targets_recorded"], 2)
        self.assertEqual(result.scoring_summary["solved"], 1)
        self.assertEqual(result.scoring_summary["review_required"], 1)
        self.assertEqual(result.exit_gates, ("scoring_results_include_evidence_refs",))

    def test_scoring_evidence_validator_rejects_result_without_evidence_refs(self) -> None:
        with self.assertRaisesRegex(ValueError, "evidence_ids"):
            validate_scoring_results_evidence_refs(
                [
                    {
                        "target_id": "mbptl-web-cache",
                        "solve_status": "failed",
                        "result": "failed",
                        "evidence_ids": [],
                    }
                ],
                target_ids=["mbptl-web-cache"],
            )

    def test_scoring_evidence_validator_rejects_non_evidence_refs(self) -> None:
        with self.assertRaisesRegex(ValueError, "evidence:<id>"):
            validate_scoring_results_evidence_refs(
                [
                    {
                        "target_id": "mbptl-web-cache",
                        "solve_status": "failed",
                        "result": "failed",
                        "evidence_ids": ["note:operator-claim"],
                    }
                ],
                target_ids=["mbptl-web-cache"],
            )

    def test_scoring_evidence_validator_rejects_missing_target_result(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing"):
            validate_scoring_results_evidence_refs(
                [
                    {
                        "target_id": "mbptl-web-cache",
                        "solve_status": "failed",
                        "result": "failed",
                        "evidence_ids": ["evidence:http-proof"],
                    }
                ],
                target_ids=["mbptl-web-cache", "mbptl-sql-auth"],
            )

    def test_scoring_evidence_validator_rejects_hidden_material(self) -> None:
        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            validate_scoring_results_evidence_refs(
                [
                    {
                        "target_id": "mbptl-web-cache",
                        "solve_status": "solved",
                        "result": "solved",
                        "evidence_ids": ["evidence:http-proof"],
                        "scoreboard_note": fixture_flag(),
                    }
                ],
                target_ids=["mbptl-web-cache"],
            )


if __name__ == "__main__":
    unittest.main()
