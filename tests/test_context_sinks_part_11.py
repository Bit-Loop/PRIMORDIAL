from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart11(ContextSinkValidatorTestsBase):
    def test_ctfd_registry_rejects_nested_truth_like_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-nested-confirmed-authority",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Nested metadata authority must not turn CTFd challenge text into target truth.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"authority": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-nested-confirmed-authority"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_ctfd_registry_rejects_nested_plural_truth_like_authorities(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-nested-confirmed-authorities",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Nested plural metadata authorities must not turn CTFd challenge text into target truth.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"authorities": ["confirmed"]},
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-nested-confirmed-authorities"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_ctfd_registry_rejects_nested_authority_kind(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-nested-evidence-kind",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Nested metadata kind must not turn CTFd challenge text into evidence.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"kind": "evidence"},
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-nested-evidence-kind"])
        self.assertTrue(any("must not create evidence" in error for error in result.errors))

    def test_ctfd_registry_rejects_nested_plural_authority_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-nested-evidence-kinds",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Nested plural metadata kinds must not turn CTFd challenge text into evidence.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"kinds": ["evidence"]},
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-nested-evidence-kinds"])
        self.assertTrue(any("must not create evidence" in error for error in result.errors))

    def test_ctfd_registry_rejects_masked_nested_unsupported_record_type(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-nested-unsupported-record-type",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Top-level challenge metadata must not mask a nested unsupported CTFd record type.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"record_type": "operator_intent"},
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-nested-unsupported-record-type"])
        self.assertTrue(any("requires challenge or scoreboard record_type" in error for error in result.errors))

    def test_ctfd_registry_rejects_plural_nested_unsupported_record_types(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-nested-unsupported-record-types",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Top-level challenge metadata must not mask nested plural unsupported CTFd record types.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"record_types": ["operator_intent"]},
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-nested-unsupported-record-types"])
        self.assertTrue(any("requires challenge or scoreboard record_type" in error for error in result.errors))

    def test_ctfd_sinks_reject_masked_nested_non_ctfd_source_type(self) -> None:
        registry_envelope = ContextEnvelope(
            ref="ctfd:registry-nested-github-source-type",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Top-level CTFd source type must not mask nested GitHub challenge metadata.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "source_type": "ctfd",
                "metadata": {"source_type": "github"},
            },
        )
        submission_envelope = ContextEnvelope(
            ref="ctfd:submission-nested-github-source-type",
            kind="ctfd_submission",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Top-level CTFd source type must not mask nested GitHub submission metadata.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "source_type": "ctfd",
                "metadata": {"source_type": "github"},
            },
        )

        registry_result = ContextSinkValidator().validate("ctfd_registry", [registry_envelope])
        submission_result = ContextSinkValidator().validate("ctfd_submission", [submission_envelope])

        self.assertFalse(registry_result.valid)
        self.assertEqual(registry_result.accepted_refs, [])
        self.assertEqual(registry_result.rejected_refs, ["ctfd:registry-nested-github-source-type"])
        self.assertTrue(any("accepts only CTFd source material" in error for error in registry_result.errors))

        self.assertFalse(submission_result.valid)
        self.assertEqual(submission_result.accepted_refs, [])
        self.assertEqual(submission_result.rejected_refs, ["ctfd:submission-nested-github-source-type"])
        self.assertTrue(any("accepts only CTFd source material" in error for error in submission_result.errors))

    def test_ctfd_sinks_reject_nested_non_ctfd_citation_metadata(self) -> None:
        registry_envelope = ContextEnvelope(
            ref="ctfd:registry-nested-github-citation",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Nested GitHub citations must not support CTFd registry metadata.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {"citations": ["github:issue-1"]},
            },
        )
        submission_envelope = ContextEnvelope(
            ref="ctfd:submission-nested-github-citation",
            kind="ctfd_submission",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Nested GitHub citations must not support CTFd submission metadata.",
            citations=["ctfd:submission-1"],
            metadata={
                "record_type": "submission_result",
                "metadata": {"citations": ["github:issue-1"]},
            },
        )

        registry_result = ContextSinkValidator().validate("ctfd_registry", [registry_envelope])
        submission_result = ContextSinkValidator().validate("ctfd_submission", [submission_envelope])

        self.assertFalse(registry_result.valid)
        self.assertEqual(registry_result.accepted_refs, [])
        self.assertEqual(registry_result.rejected_refs, ["ctfd:registry-nested-github-citation"])
        self.assertTrue(any("non-CTFd citation support" in error for error in registry_result.errors))

        self.assertFalse(submission_result.valid)
        self.assertEqual(submission_result.accepted_refs, [])
        self.assertEqual(submission_result.rejected_refs, ["ctfd:submission-nested-github-citation"])
        self.assertTrue(any("non-CTFd citation support" in error for error in submission_result.errors))

__all__ = ["ContextSinkValidatorTestsPart11"]
