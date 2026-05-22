from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


CURRENT_BINDING_METADATA = {
    "current_target_id": "target-a",
    "current_active_generation_id": "generation:2",
}


class ContextDurableSinkBindingTests(unittest.TestCase):
    def test_evidence_sink_rejects_wrong_target_and_stale_proof_records(self) -> None:
        envelopes = [
            _evidence("evidence:current-service", "target-a", "generation:2"),
            _evidence("evidence:wrong-target-service", "target-b", "generation:2"),
            _evidence("evidence:stale-service", "target-a", "generation:1"),
            _evidence("evidence:missing-generation-service", "target-a", None),
        ]

        result = ContextSinkValidator().validate("evidence", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:current-service"])
        self.assertEqual(
            result.rejected_refs,
            [
                "evidence:missing-generation-service",
                "evidence:stale-service",
                "evidence:wrong-target-service",
            ],
        )
        for reason in ("wrong_target", "stale_generation", "missing_generation_binding"):
            self.assertTrue(any(reason in error for error in result.errors), reason)

    def test_finding_sink_rejects_wrong_target_and_stale_proof_records(self) -> None:
        envelopes = [
            _finding("finding:current-service", "target-a", "generation:2"),
            _finding("finding:wrong-target-service", "target-b", "generation:2"),
            _finding("finding:stale-service", "target-a", "generation:1"),
            _finding("finding:missing-generation-service", "target-a", None),
        ]

        result = ContextSinkValidator().validate("finding", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["finding:current-service"])
        self.assertEqual(
            result.rejected_refs,
            [
                "finding:missing-generation-service",
                "finding:stale-service",
                "finding:wrong-target-service",
            ],
        )
        for reason in ("wrong_target", "stale_generation", "missing_generation_binding"):
            self.assertTrue(any(reason in error for error in result.errors), reason)


def _evidence(ref: str, target_id: str, active_generation_id: str | None) -> ContextEnvelope:
    return ContextEnvelope(
        ref=ref,
        kind="evidence",
        authority="observed",
        source_type="tool_output",
        target_id=target_id,
        active_generation_id=active_generation_id,
        purpose="evidence_review",
        sink="evidence",
        content="Observed target-specific service output.",
        citations=[ref],
        metadata=dict(CURRENT_BINDING_METADATA),
    )


def _finding(ref: str, target_id: str, active_generation_id: str | None) -> ContextEnvelope:
    return ContextEnvelope(
        ref=ref,
        kind="finding",
        authority="reviewed",
        source_type="runtime_state",
        target_id=target_id,
        active_generation_id=active_generation_id,
        purpose="finding_generation",
        sink="finding",
        content="Reviewed target-specific finding.",
        citations=["evidence:current-service"],
        metadata=dict(CURRENT_BINDING_METADATA),
    )


if __name__ == "__main__":
    unittest.main()
