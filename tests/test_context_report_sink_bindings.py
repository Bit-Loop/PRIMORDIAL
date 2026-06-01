from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextReportSinkBindingTests(unittest.TestCase):
    def test_report_sink_rejects_wrong_target_and_stale_model_target_facts(self) -> None:
        envelopes = [
            self._target_fact(
                ref="model:current-target-fact",
                target_id="target-a",
                active_generation_id="generation:2",
            ),
            self._target_fact(
                ref="model:wrong-target-fact",
                target_id="target-b",
                active_generation_id="generation:2",
            ),
            self._target_fact(
                ref="model:stale-target-fact",
                target_id="target-a",
                active_generation_id="generation:1",
            ),
            self._target_fact(
                ref="model:missing-generation-fact",
                target_id="target-a",
                active_generation_id="",
            ),
        ]

        result = ContextSinkValidator().validate("report", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["model:current-target-fact"])
        self.assertEqual(
            result.rejected_refs,
            [
                "model:missing-generation-fact",
                "model:stale-target-fact",
                "model:wrong-target-fact",
            ],
        )
        self.assertTrue(any("wrong_target" in error for error in result.errors))
        self.assertTrue(any("stale_generation" in error for error in result.errors))
        self.assertTrue(any("missing_generation_binding" in error for error in result.errors))

    def _target_fact(
        self,
        *,
        ref: str,
        target_id: str,
        active_generation_id: str,
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id=target_id,
            active_generation_id=active_generation_id,
            purpose="report_generation",
            sink="report",
            content="The target reports nginx in the HTTP banner.",
            citations=["evidence:http-banner"],
            metadata={
                "contains_target_fact": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
            },
        )


if __name__ == "__main__":
    unittest.main()
