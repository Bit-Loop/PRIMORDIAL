from __future__ import annotations

import unittest

from primordial.labs.ctf import PostmortemRecord


class PostmortemRecordContractTests(unittest.TestCase):
    def test_postmortem_record_allows_writeup_context_only_after_failure(self) -> None:
        record = PostmortemRecord.create(
            id="postmortem-juice-1",
            target_id="juice-shop-foundation",
            solve_session_id="solve-juice-1",
            solve_status="failed",
            mode="postmortem",
            source_refs=["writeup:juice-shop-foundation"],
            lessons=["Prefer evidence-backed version checks before exploitability triage."],
            generalized_changes=["Add parser fixture for normalized service titles."],
            tests_added=["tests.test_ctf_harness_hardcode_scan"],
        )

        self.assertEqual(record.output_label, "postmortem/training")
        self.assertEqual(record.source_refs, ("writeup:juice-shop-foundation",))
        self.assertEqual(record.generalized_changes, ("Add parser fixture for normalized service titles.",))

    def test_postmortem_record_rejects_writeup_context_before_completion_or_failure(self) -> None:
        with self.assertRaisesRegex(ValueError, "completion or failure"):
            PostmortemRecord.create(
                id="postmortem-juice-1",
                target_id="juice-shop-foundation",
                solve_session_id="solve-juice-1",
                solve_status="in_progress",
                mode="postmortem",
                source_refs=["writeup:juice-shop-foundation"],
                lessons=["Compare failed hypotheses against the writeup after the attempt stops."],
                generalized_changes=["Add a generic failed-hypothesis classifier."],
                tests_added=["tests.test_ctf_harness_failure_analysis"],
            )

    def test_postmortem_record_requires_generalized_tested_learning(self) -> None:
        with self.assertRaisesRegex(ValueError, "generalized changes"):
            PostmortemRecord.create(
                id="postmortem-juice-1",
                target_id="juice-shop-foundation",
                solve_session_id="solve-juice-1",
                solve_status="failed",
                mode="postmortem",
                source_refs=["writeup:juice-shop-foundation"],
                lessons=["The writeup described a missed evidence check."],
                generalized_changes=[],
                tests_added=["tests.test_ctf_harness_failure_analysis"],
            )

        with self.assertRaisesRegex(ValueError, "tests"):
            PostmortemRecord.create(
                id="postmortem-juice-1",
                target_id="juice-shop-foundation",
                solve_session_id="solve-juice-1",
                solve_status="failed",
                mode="postmortem",
                source_refs=["writeup:juice-shop-foundation"],
                lessons=["The writeup described a missed evidence check."],
                generalized_changes=["Add evidence prerequisite validation for solved state."],
                tests_added=[],
            )

    def test_postmortem_record_rejects_target_specific_solution_encoding(self) -> None:
        with self.assertRaisesRegex(ValueError, "target-specific"):
            PostmortemRecord.create(
                id="postmortem-juice-1",
                target_id="juice-shop-foundation",
                solve_session_id="solve-juice-1",
                solve_status="failed",
                mode="postmortem",
                source_refs=["writeup:juice-shop-foundation"],
                lessons=["If target is juice-shop-foundation, request /rest/admin/application-configuration."],
                generalized_changes=["Hardcode juice-shop-foundation route sequence."],
                tests_added=["tests.test_ctf_harness_hardcode_scan"],
            )

    def test_postmortem_record_rejects_raw_flag_material(self) -> None:
        with self.assertRaisesRegex(ValueError, "raw flag"):
            PostmortemRecord.create(
                id="postmortem-juice-1",
                target_id="juice-shop-foundation",
                solve_session_id="solve-juice-1",
                solve_status="failed",
                mode="postmortem",
                source_refs=["writeup:juice-shop-foundation"],
                lessons=["The failed path ended at ctf{training-only-hidden-value}."],
                generalized_changes=["Add redaction tests for captured secrets."],
                tests_added=["tests.test_ctf_harness_hardcode_scan"],
            )

    def test_postmortem_record_rejects_raw_flag_material_in_payload_identity(self) -> None:
        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            PostmortemRecord.create(
                id="postmortem-ctf{training-only-hidden-value}",
                target_id="juice-shop-foundation",
                solve_session_id="solve-juice-1",
                solve_status="failed",
                mode="postmortem",
                source_refs=["writeup:juice-shop-foundation"],
                lessons=["Compare failed hypotheses against observed evidence."],
                generalized_changes=["Add generalized evidence prerequisite checks."],
                tests_added=["tests.test_ctf_harness_solve_verification"],
            )


if __name__ == "__main__":
    unittest.main()
