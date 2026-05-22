from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextSinkBoundaryTests(unittest.TestCase):
    def test_sink_validator_rejects_envelope_declared_for_different_sink(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:scan-1",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="evidence_review",
            sink="notion_export",
            content="Observed scanner output must not enter a sink it was not wrapped for.",
            citations=["evidence:scan-1"],
        )

        result = ContextSinkValidator().validate("evidence", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:scan-1"])
        self.assertTrue(any("sink mismatch" in error for error in result.errors))
        self.assertTrue(any("notion_export" in error and "evidence" in error for error in result.errors))

    def test_sink_validator_normalizes_human_readable_sink_names_before_dispatch(self) -> None:
        envelope = ContextEnvelope(
            ref="model:uncited-export-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="export",
            sink="Notion export",
            content="Uncited AI summary must not bypass Notion export quarantine.",
            citations=[],
        )

        result = ContextSinkValidator().validate("Notion export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:uncited-export-summary"])
        self.assertTrue(any("missing citations" in error for error in result.errors))
        self.assertEqual(result.warnings, [])

    def test_unknown_operational_sink_fails_closed(self) -> None:
        envelope = ContextEnvelope(
            ref="model:target-state-cache",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="target_state_answer",
            sink="target_state_cache",
            content="Unknown operational sinks must not bypass target-state citation rules.",
            citations=["rag:methodology"],
            metadata={"contains_target_fact": True},
        )

        result = ContextSinkValidator().validate("target_state_cache", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:target-state-cache"])
        self.assertTrue(any("unknown operational sink" in error for error in result.errors))
        self.assertEqual(result.warnings, [])

    def test_unknown_operational_sink_name_fails_closed_even_with_advisory_purpose(self) -> None:
        envelope = ContextEnvelope(
            ref="model:miswrapped-target-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="casual_advisory",
            sink="current_target_summary",
            content="Operational-looking sink names must not bypass sink rules with a casual purpose.",
            citations=["rag:methodology"],
            metadata={"contains_target_fact": True},
        )

        result = ContextSinkValidator().validate("current_target_summary", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:miswrapped-target-summary"])
        self.assertTrue(any("unknown operational sink" in error for error in result.errors))
        self.assertEqual(result.warnings, [])

    def test_discord_notification_rejects_string_encoded_boundary_flags(self) -> None:
        evidence_like = ContextEnvelope(
            ref="model:display-summary-as-evidence",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="discord_notification",
            sink="discord_notification",
            content="The model summary is formatted as proof of exploitability.",
            citations=["evidence:scan-1"],
            metadata={"labels": ["derived"], "Renders as evidence": "true"},
        )
        approval_like = ContextEnvelope(
            ref="task:display-approval-implied",
            kind="candidate_task",
            authority="advisory",
            source_type="vuln_intel",
            purpose="discord_notification",
            sink="discord_notification",
            content="Exploit validation is ready to run.",
            citations=["rag:cve-advisory"],
            metadata={"labels": ["advisory"], "Implies approval": "yes"},
        )

        result = ContextSinkValidator().validate("discord_notification", [evidence_like, approval_like])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:display-summary-as-evidence", "task:display-approval-implied"])
        self.assertTrue(any("must not render derived context as evidence" in error for error in result.errors))
        self.assertTrue(any("must not imply approval" in error for error in result.errors))

    def test_discord_notification_rejects_non_evidence_source_proof_records(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:scan-1",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                purpose="discord_notification",
                sink="discord_notification",
                content="Observed scanner output may be notified as evidence.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="evidence:ai-summary",
                kind="evidence",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                purpose="discord_notification",
                sink="discord_notification",
                content="AI output must not be notified as an evidence record.",
                citations=["evidence:scan-1"],
                metadata={"labels": ["advisory"]},
            ),
            ContextEnvelope(
                ref="finding:vuln-intel",
                kind="finding",
                authority="advisory",
                source_type="vuln_intel",
                target_id="target-a",
                purpose="discord_notification",
                sink="discord_notification",
                content="Vulnerability intelligence must not be notified as a finding record.",
                citations=["rag:cve-advisory"],
                metadata={"labels": ["advisory"]},
            ),
        ]

        result = ContextSinkValidator().validate("discord_notification", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:scan-1"])
        self.assertEqual(result.rejected_refs, ["evidence:ai-summary", "finding:vuln-intel"])
        self.assertTrue(any("non-evidence source proof record" in error for error in result.errors))

    def test_github_issue_rejects_target_finding_records(self) -> None:
        finding = ContextEnvelope(
            ref="finding:github-draft",
            kind="finding",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_issue",
            content="GitHub issues must not carry target-shaped finding records.",
            citations=["github:issue-1"],
        )

        result = ContextSinkValidator().validate("github_issue", [finding])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["finding:github-draft"])
        self.assertTrue(any("must not create target authority" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
