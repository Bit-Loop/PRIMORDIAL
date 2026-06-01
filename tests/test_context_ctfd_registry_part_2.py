from __future__ import annotations

from tests.test_context_ctfd_registry_common import *


class CTFdRegistrySinkTestsPart2(CTFdRegistrySinkTestsBase):
    def test_ctfd_sinks_reject_target_fact_markers(self) -> None:
        registry_target_fact = self._registry_envelope(
            "ctfd:target-fact-challenge",
            contains_target_fact=True,
        )
        submission_target_fact = self._submission_envelope(
            "ctfd:target-fact-submission",
            kind="ctfd_submission",
        )
        submission_target_fact.metadata["target factual claim"] = "yes"
        ordinary_registry = self._registry_envelope("ctfd:ordinary-challenge")
        ordinary_submission = self._submission_envelope(
            "ctfd:ordinary-submission",
            kind="ctfd_submission",
        )

        registry_result = ContextSinkValidator().validate(
            "ctfd_registry",
            [registry_target_fact, ordinary_registry],
        )
        submission_result = ContextSinkValidator().validate(
            "ctfd_submission",
            [submission_target_fact, ordinary_submission],
        )

        self.assertFalse(registry_result.valid)
        self.assertEqual(registry_result.accepted_refs, ["ctfd:ordinary-challenge"])
        self.assertEqual(registry_result.rejected_refs, ["ctfd:target-fact-challenge"])
        self.assertTrue(any("target fact" in error for error in registry_result.errors))

        self.assertFalse(submission_result.valid)
        self.assertEqual(submission_result.accepted_refs, ["ctfd:ordinary-submission"])
        self.assertEqual(submission_result.rejected_refs, ["ctfd:target-fact-submission"])
        self.assertTrue(any("target fact" in error for error in submission_result.errors))

__all__ = ["CTFdRegistrySinkTestsPart2"]
