from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart12(ContextSinkValidatorTestsBase):
    def test_ctfd_sinks_reject_nested_non_ctfd_citation_ref_metadata(self) -> None:
        registry_envelope = ContextEnvelope(
            ref="ctfd:registry-nested-github-citation-ref",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Nested GitHub citation refs must not support CTFd registry metadata.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"citation_ref": "github:issue-1"},
            },
        )
        submission_envelope = ContextEnvelope(
            ref="ctfd:submission-nested-github-citation-ref",
            kind="ctfd_submission",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Nested GitHub citation refs must not support CTFd submission metadata.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "metadata": {"citation_ref": "github:issue-1"},
            },
        )

        registry_result = ContextSinkValidator().validate("ctfd_registry", [registry_envelope])
        submission_result = ContextSinkValidator().validate("ctfd_submission", [submission_envelope])

        self.assertFalse(registry_result.valid)
        self.assertEqual(registry_result.accepted_refs, [])
        self.assertEqual(registry_result.rejected_refs, ["ctfd:registry-nested-github-citation-ref"])
        self.assertTrue(any("non-CTFd citation support" in error for error in registry_result.errors))

        self.assertFalse(submission_result.valid)
        self.assertEqual(submission_result.accepted_refs, [])
        self.assertEqual(submission_result.rejected_refs, ["ctfd:submission-nested-github-citation-ref"])
        self.assertTrue(any("non-CTFd citation support" in error for error in submission_result.errors))

    def test_ctfd_submission_rejects_context_restrictions_that_exclude_submission(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="ctfd:prompt-only-submission",
                kind="submission_result",
                authority="advisory",
                source_type="ctfd",
                purpose="ctfd_submission",
                sink="ctfd_submission",
                content="Prompt-only submission metadata must not enter the durable CTFd submission sink.",
                citations=["ctfd:submission-1"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"], "record_type": "submission_result"},
            ),
            ContextEnvelope(
                ref="ctfd:submission-denied-result",
                kind="submission_result",
                authority="advisory",
                source_type="ctfd",
                purpose="ctfd_submission",
                sink="ctfd_submission",
                content="CTFd-submission-denied metadata must not enter the durable CTFd submission sink.",
                citations=["ctfd:submission-2"],
                invalid_for=["ctfd_submission"],
                metadata={"invalid_for": ["ctfd_submission"], "record_type": "submission_result"},
            ),
        ]

        result = ContextSinkValidator().validate("ctfd_submission", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:prompt-only-submission", "ctfd:submission-denied-result"])
        self.assertTrue(any("valid_for excludes ctfd_submission" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes ctfd_submission" in error for error in result.errors))

    def test_ctfd_submission_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-export-url",
            kind="submission_result",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Generated export URLs must not enter the durable CTFd submission sink.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-export-url"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_ctfd_submission_rejects_nested_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-nested-export-url",
            kind="submission_result",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Nested generated export URLs must not enter the durable CTFd submission sink.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "metadata": {
                    "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
                },
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-nested-export-url"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_ctfd_submission_rejects_nested_flag_submission_without_solve_intent(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-nested-flag",
            kind="submission_result",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Nested CTFd flag submission markers must still require solve intent.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "metadata": {"submission_type": "flag"},
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-nested-flag"])
        self.assertTrue(any("requires ctf solve intent" in error for error in result.errors))

    def test_ctfd_submission_rejects_masked_nested_flag_submission_without_solve_intent(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-masked-nested-flag",
            kind="submission_result",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Top-level submission type must not mask a nested flag submission marker.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "submission_type": "submission_result",
                "metadata": {"submission_type": "flag"},
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-masked-nested-flag"])
        self.assertTrue(any("requires ctf solve intent" in error for error in result.errors))

    def test_ctfd_submission_rejects_plural_nested_flag_submission_without_solve_intent(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-nested-flag-types",
            kind="submission_result",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Nested plural CTFd flag submission markers must still require solve intent.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "submission_type": "submission_result",
                "metadata": {"submission_types": ["flag_submission"]},
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-nested-flag-types"])
        self.assertTrue(any("requires ctf solve intent" in error for error in result.errors))

    def test_ctfd_submission_rejects_masked_nested_recon_only_intent_for_flag_submission(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-masked-nested-recon-only-intent",
            kind="submission_result",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Top-level solve intent must not mask a nested recon-only flag submission intent.",
            citations=["ctfd:submission-1"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "record_type": "submission_result",
                "submission_type": "flag",
                "metadata": {"active_intent": "recon_only"},
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-masked-nested-recon-only-intent"])
        self.assertTrue(any("requires ctf solve intent" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart12"]
