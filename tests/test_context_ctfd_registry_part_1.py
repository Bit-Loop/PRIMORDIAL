from __future__ import annotations

from tests.test_context_ctfd_registry_common import *


class CTFdRegistrySinkTestsPart1(CTFdRegistrySinkTestsBase):
    def test_ctfd_registry_accepts_challenge_and_scoreboard_metadata_only(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="ctfd:challenge-101",
                kind="ctfd_ref",
                authority="asserted",
                source_type="ctfd",
                purpose="ctf_benchmark",
                sink="ctfd_registry",
                content="Challenge metadata projection.",
                citations=["ctfd:challenge-101"],
                metadata={
                    "record_type": "challenge_metadata",
                    "challenge_id": "101",
                    "category": "web",
                    "value": 100,
                    "target_authority": False,
                },
            ),
            ContextEnvelope(
                ref="ctfd:scoreboard-101",
                kind="scoreboard_projection",
                authority="asserted",
                source_type="ctfd",
                purpose="ctf_benchmark",
                sink="ctfd_registry",
                content="Scoreboard projection says the challenge is unsolved.",
                citations=["ctfd:challenge-101"],
                metadata={
                    "record_type": "scoreboard_projection",
                    "challenge_id": "101",
                    "solved": False,
                    "score": 0,
                },
            ),
        ]

        result = ContextSinkValidator().validate("ctfd_registry", envelopes)

        self.assertTrue(result.valid)
        self.assertEqual(result.accepted_refs, ["ctfd:challenge-101", "ctfd:scoreboard-101"])
        self.assertEqual(result.rejected_refs, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])

    def test_ctfd_registry_rejects_authority_mutations_and_hidden_flag_material(self) -> None:
        envelopes = [
            self._registry_envelope("ctfd:evidence", kind="evidence", creates_evidence=True),
            self._registry_envelope("ctfd:approval", kind="approval", creates_approval=True),
            self._registry_envelope("ctfd:scope", changes_scope=True),
            self._registry_envelope("ctfd:intent", kind="operator_intent", changes_operator_intent=True),
            self._registry_envelope("ctfd:target-truth", creates_target_authority=True),
            self._registry_envelope("ctfd:action", authorizes_target_action=True),
            self._registry_envelope("ctfd:raw-flag", contains_raw_flag=True),
            self._registry_envelope("ctfd:hidden-flag", contains_raw_expected_flag=True),
        ]

        result = ContextSinkValidator().validate("ctfd_registry", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(
            result.rejected_refs,
            [
                "ctfd:action",
                "ctfd:approval",
                "ctfd:evidence",
                "ctfd:hidden-flag",
                "ctfd:intent",
                "ctfd:raw-flag",
                "ctfd:scope",
                "ctfd:target-truth",
            ],
        )
        self.assertEqual(result.accepted_refs, [])
        joined_errors = "\n".join(result.errors)
        for expected in (
            "evidence",
            "approval",
            "scope",
            "Operator Intent",
            "target authority",
            "target action",
            "raw flag",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, joined_errors)

    def test_ctfd_submission_rejects_authority_kinds_without_flags(self) -> None:
        envelopes = [
            self._submission_envelope("ctfd:submission-approval", kind="approval"),
            self._submission_envelope("ctfd:submission-scope", kind="scope"),
            self._submission_envelope("ctfd:submission-intent", kind="operator_intent"),
            self._submission_envelope("ctfd:submission-policy", kind="policy_decision"),
        ]

        result = ContextSinkValidator().validate("ctfd_submission", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            [
                "ctfd:submission-approval",
                "ctfd:submission-intent",
                "ctfd:submission-policy",
                "ctfd:submission-scope",
            ],
        )
        joined_errors = "\n".join(result.errors)
        for expected in ("approval", "Operator Intent", "policy decision", "scope"):
            with self.subTest(expected=expected):
                self.assertIn(expected, joined_errors)

    def test_ctfd_submission_rejects_target_finding_records(self) -> None:
        envelope = self._submission_envelope("ctfd:submission-finding", kind="finding")

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-finding"])
        self.assertTrue(any("target finding" in error for error in result.errors))

    def test_ctfd_submission_accepts_only_ctfd_submission_results(self) -> None:
        valid_submission = self._submission_envelope("ctfd:submission-result", kind="ctfd_submission")
        github_wrapped_submission = ContextEnvelope(
            ref="ctfd:github-wrapped-submission",
            kind="ctfd_submission",
            authority="asserted",
            source_type="github",
            purpose="ctf_benchmark",
            sink="ctfd_submission",
            content="GitHub issue prose must not become a CTFd submission result.",
            citations=["github:issue-1"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "record_type": "submission_result",
                "challenge_id": "101",
            },
        )
        wrong_kind_submission = self._submission_envelope("ctfd:submission-github-ref", kind="github_ref")
        wrong_record_type_submission = self._submission_envelope(
            "ctfd:submission-challenge-metadata",
            kind="ctfd_submission",
        )
        wrong_record_type_submission.metadata["record_type"] = "challenge_metadata"

        result = ContextSinkValidator().validate(
            "ctfd_submission",
            [
                valid_submission,
                github_wrapped_submission,
                wrong_kind_submission,
                wrong_record_type_submission,
            ],
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["ctfd:submission-result"])
        self.assertEqual(
            result.rejected_refs,
            [
                "ctfd:github-wrapped-submission",
                "ctfd:submission-challenge-metadata",
                "ctfd:submission-github-ref",
            ],
        )
        self.assertTrue(any("accepts only CTFd source material" in error for error in result.errors))
        self.assertTrue(any("accepts only submission result material" in error for error in result.errors))
        self.assertTrue(any("requires submission_result record_type" in error for error in result.errors))

    def test_ctfd_sinks_reject_truth_like_authority_labels(self) -> None:
        registry_envelope = self._registry_envelope(
            "ctfd:authoritative-challenge",
            authority="authoritative",
        )
        confirmed_registry_envelope = self._registry_envelope(
            "ctfd:confirmed-challenge",
            authority="confirmed",
        )
        submission_envelope = self._submission_envelope(
            "ctfd:observed-submission",
            kind="ctfd_submission",
            authority="observed",
        )

        registry_result = ContextSinkValidator().validate(
            "ctfd_registry",
            [registry_envelope, confirmed_registry_envelope],
        )
        submission_result = ContextSinkValidator().validate("ctfd_submission", [submission_envelope])

        self.assertFalse(registry_result.valid)
        self.assertEqual(registry_result.accepted_refs, [])
        self.assertEqual(registry_result.rejected_refs, ["ctfd:authoritative-challenge", "ctfd:confirmed-challenge"])
        self.assertTrue(any("truth-like authority" in error for error in registry_result.errors))

        self.assertFalse(submission_result.valid)
        self.assertEqual(submission_result.accepted_refs, [])
        self.assertEqual(submission_result.rejected_refs, ["ctfd:observed-submission"])
        self.assertTrue(any("truth-like authority" in error for error in submission_result.errors))

    def test_ctfd_metadata_rejects_non_ctfd_citation_support(self) -> None:
        registry_envelope = self._registry_envelope("ctfd:evidence-backed-challenge")
        registry_envelope.citations = ["evidence:scan-1"]
        submission_envelope = self._submission_envelope(
            "ctfd:github-backed-submission",
            kind="ctfd_submission",
        )
        submission_envelope.citations = ["github:issue-1"]

        registry_result = ContextSinkValidator().validate("ctfd_registry", [registry_envelope])
        submission_result = ContextSinkValidator().validate("ctfd_submission", [submission_envelope])

        self.assertFalse(registry_result.valid)
        self.assertEqual(registry_result.accepted_refs, [])
        self.assertEqual(registry_result.rejected_refs, ["ctfd:evidence-backed-challenge"])
        self.assertTrue(any("non-CTFd citation support" in error for error in registry_result.errors))

        self.assertFalse(submission_result.valid)
        self.assertEqual(submission_result.accepted_refs, [])
        self.assertEqual(submission_result.rejected_refs, ["ctfd:github-backed-submission"])
        self.assertTrue(any("non-CTFd citation support" in error for error in submission_result.errors))

__all__ = ["CTFdRegistrySinkTestsPart1"]
