from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextCollaborationBindingTests(unittest.TestCase):
    def test_discord_notification_rejects_wrong_target_and_stale_model_target_facts(self) -> None:
        envelopes = [
            self._target_fact(
                ref="model:current-discord-fact",
                target_id="target-a",
                active_generation_id="generation:2",
                content="Current target notification summary.",
            ),
            self._target_fact(
                ref="model:wrong-target-discord-fact",
                target_id="target-b",
                active_generation_id="generation:2",
                content="Wrong target notification summary.",
            ),
            self._target_fact(
                ref="model:stale-discord-fact",
                target_id="target-a",
                active_generation_id="generation:1",
                content="Stale generation notification summary.",
            ),
            self._target_fact(
                ref="model:missing-generation-discord-fact",
                target_id="target-a",
                active_generation_id="",
                content="Missing generation notification summary.",
            ),
        ]

        result = ContextSinkValidator().validate("discord_notification", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["model:current-discord-fact"])
        self.assertEqual(
            result.rejected_refs,
            [
                "model:missing-generation-discord-fact",
                "model:stale-discord-fact",
                "model:wrong-target-discord-fact",
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
        content: str,
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id=target_id,
            active_generation_id=active_generation_id,
            purpose="discord_notification",
            sink="discord_notification",
            content=content,
            citations=["evidence:http-banner"],
            metadata={
                "contains_target_fact": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "labels": ["advisory"],
            },
        )


if __name__ == "__main__":
    unittest.main()
