from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart8(ContextSinkValidatorTestsBase):
    def test_discord_notification_quarantines_nested_advisory_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="status:nested-ai-output-notice",
            kind="test_status",
            authority="asserted",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested AI-output source metadata must still require an advisory notification label.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"source_type": "ai_output"},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["status:nested-ai-output-notice"])
        self.assertTrue(any("requires advisory or unverified label" in error for error in result.errors))

    def test_discord_notification_quarantines_plural_nested_derived_authorities(self) -> None:
        envelope = ContextEnvelope(
            ref="status:nested-derived-authorities-notice",
            kind="test_status",
            authority="asserted",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested plural derived authorities must still require an advisory notification label.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"authorities": ["derived"]},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["status:nested-derived-authorities-notice"])
        self.assertTrue(any("requires advisory or unverified label" in error for error in result.errors))

    def test_discord_notification_quarantines_plural_nested_advisory_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="status:nested-rag-kinds-notice",
            kind="test_status",
            authority="asserted",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested plural advisory kinds must still require an advisory notification label.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"kinds": ["rag"]},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["status:nested-rag-kinds-notice"])
        self.assertTrue(any("requires advisory or unverified label" in error for error in result.errors))

    def test_direct_discord_notification_quarantines_plural_nested_advisory_source_types(self) -> None:
        envelope = ContextEnvelope(
            ref="status:direct-nested-ai-output-notice",
            kind="test_status",
            authority="asserted",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested plural AI-output source metadata must still require an advisory notification label.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"source_types": ["ai_output"]},
            },
        )

        decision = validate_collaboration_sink(
            "discord_notification",
            envelope,
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertEqual(decision.action, "quarantine")
        self.assertIn("requires advisory or unverified label", decision.message)

    def test_discord_notification_rejects_generated_export_source_path(self) -> None:
        envelope = ContextEnvelope(
            ref="model:discord-export-path-summary",
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
                "labels": ["advisory"],
                "source_file": "findings/notion/target-a/notion-export.md",
                "source_refs": ["evidence:http-banner"],
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:discord-export-path-summary"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_discord_notification_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="model:discord-export-url-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Generated export URLs must not loop into operator notification context.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["advisory"],
                "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
                "source_refs": ["evidence:http-banner"],
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:discord-export-url-summary"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_discord_notification_rejects_context_restrictions_that_exclude_discord(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="note:prompt-only-discord-note",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                purpose="discord_notification",
                sink="discord_notification",
                content="Prompt-only operator notes must not be projected into Discord notifications.",
                citations=["note:prompt-only-discord-note"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"]},
            ),
            ContextEnvelope(
                ref="note:discord-denied-note",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                purpose="discord_notification",
                sink="discord_notification",
                content="Discord-denied operator notes must not be projected into Discord notifications.",
                citations=["note:discord-denied-note"],
                invalid_for=["discord_notification"],
                metadata={"invalid_for": ["discord_notification"]},
            ),
        ]

        result = ContextSinkValidator().validate("discord_notification", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:discord-denied-note", "note:prompt-only-discord-note"])
        self.assertTrue(any("valid_for excludes discord_notification" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes discord_notification" in error for error in result.errors))

    def test_github_issue_rejects_generated_export_source_path(self) -> None:
        envelope = ContextEnvelope(
            ref="github:export-path-failure-analysis",
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
                "redacted": True,
                "source_file": "findings/notion/target-a/notion-export.md",
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:export-path-failure-analysis"])
        self.assertTrue(any("generated export" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart8"]
