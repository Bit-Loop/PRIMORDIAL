from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextGeneratedExportRecursionTests(unittest.TestCase):
    def test_discord_notification_rejects_generated_export_origin(self) -> None:
        envelope = ContextEnvelope(
            ref="model:discord-export-recursion",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Generated export text must not loop into operator notification context.",
            citations=["evidence:http-banner"],
            metadata={
                "origin": "generated_export",
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
        self.assertEqual(result.rejected_refs, ["model:discord-export-recursion"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_github_issue_rejects_generated_export_origin(self) -> None:
        envelope = ContextEnvelope(
            ref="github:export-recursive-failure-analysis",
            kind="failure_analysis",
            authority="advisory",
            source_type="failure_analysis",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Generated export text must not become engineering ledger context.",
            citations=[],
            metadata={
                "context_type": "failure_analysis",
                "origin": "generated_export",
                "redacted": True,
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:export-recursive-failure-analysis"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_task_metadata_rejects_generated_export_origin_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:export-origin-service-check",
            kind="candidate_task",
            authority="advisory",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Generated export text must not authorize executable task metadata.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "Active intent": "ctf_solve_assisted",
                "Action class": "Tool execution",
                "Creates executable task": "true",
                "Current active generation id": "generation:2",
                "Supporting evidence refs": ["evidence:observed-service"],
                "origin": "generated_export",
            },
        )

        result = ContextSinkValidator().validate(
            "task_metadata",
            [envelope],
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["task:export-origin-service-check"])
        self.assertTrue(any("generated export" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
