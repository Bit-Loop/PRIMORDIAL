from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextCollaborationCitationRefTests(unittest.TestCase):
    def test_discord_notification_rejects_unresolved_target_fact_evidence_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:discord-target-fact",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Operator notification says target-a has tcp/80 open.",
            citations=["evidence:made-up"],
            metadata={
                "contains_target_fact": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "labels": ["advisory"],
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:discord-target-fact"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))
        self.assertTrue(any("evidence:made-up" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
