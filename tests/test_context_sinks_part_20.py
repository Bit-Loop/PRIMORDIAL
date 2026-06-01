from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart20(ContextSinkValidatorTestsBase):
    def test_notion_export_quarantines_nested_writeups_disabled_writeup(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:export-writeups-disabled",
            kind="rag",
            authority="advisory",
            source_type="writeup",
            purpose="export",
            sink="notion_export",
            content="Notion export must not project writeup-denied material.",
            citations=["rag:export-writeups-disabled"],
            metadata={"metadata": {"writeups_allowed": False}},
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_rag_refs={"rag:export-writeups-disabled"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["rag:export-writeups-disabled"])
        self.assertTrue(any("writeups_forbidden" in error for error in result.errors))

    def test_notion_export_quarantines_model_refs_against_quarantined_operator_note(self) -> None:
        note = ContextEnvelope(
            ref="note:bad-export-provenance",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="export",
            sink="notion_export",
            content="Export note provenance must not cite unresolved evidence.",
            citations=["note:bad-export-provenance", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )
        model_summary = ContextEnvelope(
            ref="model:bad-export-note-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="export",
            sink="notion_export",
            content="Export model output must not resolve against a quarantined operator note.",
            citations=["note:bad-export-provenance"],
            metadata={"source_refs": ["note:bad-export-provenance"]},
        )

        result = ContextSinkValidator().validate("notion_export", [note, model_summary], known_evidence_refs=set())

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:bad-export-note-backed", "note:bad-export-provenance"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))

    def test_direct_notion_export_quarantines_operator_note_with_unsupported_source_refs(self) -> None:
        note = ContextEnvelope(
            ref="note:direct-export-unsupported-source-refs",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="export",
            sink="notion_export",
            content="Direct Notion export validation must not let operator notes hide unsupported provenance.",
            citations=["note:direct-export-unsupported-source-refs"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        decision = validate_notion_export_envelope(note, set())

        self.assertEqual(decision.action, "quarantine")
        self.assertIn("unsupported source_refs", decision.message)
        self.assertIn("github:issue-42", decision.message)

    def test_notion_export_quarantines_context_restrictions_that_exclude_export(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="note:prompt-only-export-note",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                purpose="cleanup",
                sink="notion_export",
                content="Prompt-only operator notes must not be projected into Notion export.",
                citations=["note:prompt-only-export-note"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"]},
            ),
            ContextEnvelope(
                ref="note:notion-export-denied-note",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                purpose="cleanup",
                sink="notion_export",
                content="Notion-export-denied operator notes must not be projected into Notion export.",
                citations=["note:notion-export-denied-note"],
                invalid_for=["notion_export"],
                metadata={"invalid_for": ["notion_export"]},
            ),
        ]

        result = ContextSinkValidator().validate("notion_export", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["note:notion-export-denied-note", "note:prompt-only-export-note"])
        self.assertTrue(any("valid_for excludes notion_export" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes notion_export" in error for error in result.errors))

    def test_notion_inbox_rejects_context_restrictions_that_exclude_inbox(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="note:prompt-only-inbox-note",
                kind="operator_note",
                authority="asserted",
                source_type="notion",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="Prompt-only Notion edits must not enter the Notion inbox sink.",
                citations=["note:prompt-only-inbox-note"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"], "edit_source": "user"},
            ),
            ContextEnvelope(
                ref="note:inbox-denied-note",
                kind="operator_note",
                authority="asserted",
                source_type="notion",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="Notion-inbox-denied edits must not enter the Notion inbox sink.",
                citations=["note:inbox-denied-note"],
                invalid_for=["notion_inbox"],
                metadata={"invalid_for": ["notion_inbox"], "edit_source": "user"},
            ),
        ]

        result = ContextSinkValidator().validate("notion_inbox", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:inbox-denied-note", "note:prompt-only-inbox-note"])
        self.assertTrue(any("valid_for excludes notion_inbox" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes notion_inbox" in error for error in result.errors))

    def test_notion_inbox_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="note:inbox-export-url",
            kind="external_reference",
            authority="advisory",
            source_type="notion",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="Inbound Notion references must not reintroduce generated export URLs.",
            citations=["note:inbox-export-url"],
            metadata={
                "edit_source": "user",
                "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
            },
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:inbox-export-url"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_notion_inbox_rejects_nested_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="note:inbox-nested-export-url",
            kind="external_reference",
            authority="advisory",
            source_type="notion",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="Inbound Notion references must not hide generated export URLs in nested metadata.",
            citations=["note:inbox-nested-export-url"],
            metadata={
                "edit_source": "user",
                "metadata": {
                    "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
                },
            },
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:inbox-nested-export-url"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_notion_inbox_rejects_nested_confirmed_finding_status(self) -> None:
        envelope = ContextEnvelope(
            ref="note:inbox-nested-confirmed-finding",
            kind="finding_draft_delta",
            authority="advisory",
            source_type="notion",
            target_id="target-a",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="Inbound Notion edits must not hide confirmed finding status in nested metadata.",
            citations=["note:inbox-nested-confirmed-finding"],
            metadata={
                "edit_source": "user",
                "metadata": {"finding_status": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:inbox-nested-confirmed-finding"])
        self.assertTrue(any("confirmed finding" in error for error in result.errors))

    def test_notion_inbox_rejects_nested_truth_like_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="note:inbox-nested-confirmed-authority",
            kind="external_reference",
            authority="advisory",
            source_type="notion",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="Nested Notion authority must not turn an inbox proposal into target truth.",
            citations=["note:inbox-nested-confirmed-authority"],
            metadata={
                "edit_source": "user",
                "metadata": {"authority": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:inbox-nested-confirmed-authority"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart20"]
