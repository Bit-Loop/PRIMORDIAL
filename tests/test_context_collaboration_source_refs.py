from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextCollaborationSourceRefTests(unittest.TestCase):
    def test_discord_notification_rejects_ai_summary_with_unsupported_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:discord-github-source-ref",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Discord summaries must not hide unsupported collaboration provenance.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["advisory"],
                "source_refs": ["evidence:http-banner", "github:issue-42"],
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:discord-github-source-ref"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))
        self.assertTrue(any("github:issue-42" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
