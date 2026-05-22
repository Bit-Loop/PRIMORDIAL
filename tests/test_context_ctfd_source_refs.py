from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class CTFdSourceRefTests(unittest.TestCase):
    def test_ctfd_registry_rejects_non_ctfd_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:challenge-with-evidence-source",
            kind="ctfd_ref",
            authority="asserted",
            source_type="ctfd",
            purpose="ctf_benchmark",
            sink="ctfd_registry",
            content="CTFd challenge metadata must not hide evidence support.",
            citations=["ctfd:challenge-101"],
            metadata={
                "record_type": "challenge_metadata",
                "challenge_id": "101",
                "source_refs": ["ctfd:challenge-101", "evidence:http-banner"],
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:challenge-with-evidence-source"])
        self.assertTrue(any("non-CTFd source_refs" in error for error in result.errors))
        self.assertTrue(any("evidence:http-banner" in error for error in result.errors))

    def test_ctfd_sinks_reject_malformed_source_refs_metadata(self) -> None:
        registry_envelope = ContextEnvelope(
            ref="ctfd:challenge-malformed-source-refs",
            kind="ctfd_ref",
            authority="asserted",
            source_type="ctfd",
            purpose="ctf_benchmark",
            sink="ctfd_registry",
            content="CTFd challenge metadata must not hide malformed provenance.",
            citations=["ctfd:challenge-101"],
            metadata={
                "record_type": "challenge_metadata",
                "challenge_id": "101",
                "source_refs": {"primary": "ctfd:challenge-101"},
            },
        )
        submission_envelope = ContextEnvelope(
            ref="ctfd:submission-malformed-source-refs",
            kind="ctfd_submission",
            authority="asserted",
            source_type="ctfd",
            purpose="ctf_benchmark",
            sink="ctfd_submission",
            content="CTFd submission metadata must not hide malformed provenance.",
            citations=["ctfd:challenge-101"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "record_type": "submission_result",
                "challenge_id": "101",
                "source_refs": {"primary": "ctfd:challenge-101"},
            },
        )

        registry_result = ContextSinkValidator().validate("ctfd_registry", [registry_envelope])
        submission_result = ContextSinkValidator().validate("ctfd_submission", [submission_envelope])

        self.assertFalse(registry_result.valid)
        self.assertEqual(registry_result.accepted_refs, [])
        self.assertEqual(registry_result.rejected_refs, ["ctfd:challenge-malformed-source-refs"])
        self.assertTrue(any("malformed source_refs" in error for error in registry_result.errors))

        self.assertFalse(submission_result.valid)
        self.assertEqual(submission_result.accepted_refs, [])
        self.assertEqual(submission_result.rejected_refs, ["ctfd:submission-malformed-source-refs"])
        self.assertTrue(any("malformed source_refs" in error for error in submission_result.errors))


if __name__ == "__main__":
    unittest.main()
