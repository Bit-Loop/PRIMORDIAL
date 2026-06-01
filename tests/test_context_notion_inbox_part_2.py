from __future__ import annotations

from tests.test_context_notion_inbox_common import *


class NotionInboxSinkTestsPart2(NotionInboxSinkTestsBase):
    def test_notion_inbox_quarantines_human_readable_user_edit_to_primordial_owned_block(self) -> None:
        envelope = ContextEnvelope(
            ref="notion:display-runtime-state-block-edit",
            kind="operator_note",
            authority="asserted",
            source_type="notion",
            target_id="target-a",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="User edit to a Primordial-owned runtime state block.",
            citations=["notion:display-runtime-state-block-edit"],
            metadata={
                "Block owner": "Primordial",
                "Edit source": "Automation",
                "Edited by user": True,
                "Section": "Runtime State",
                "Local entity type": "runtime_state",
            },
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, [])
        self.assertEqual(result.quarantined_refs, ["notion:display-runtime-state-block-edit"])
        self.assertTrue(any("manual review" in error for error in result.errors))
        self.assertTrue(any("Primordial-owned" in error for error in result.errors))

    def test_notion_inbox_rejects_non_notion_source_types(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="notion:operator-note",
                kind="operator_note",
                authority="asserted",
                source_type="notion",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="A Notion-authored operator note may enter as an assertion.",
                citations=["notion:operator-note"],
            ),
            ContextEnvelope(
                ref="chat:operator-note",
                kind="operator_note",
                authority="asserted",
                source_type="chat",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="Chat must not enter through the Notion inbox path.",
                citations=["chat:operator-note"],
            ),
            ContextEnvelope(
                ref="model:candidate-task",
                kind="candidate_task",
                authority="asserted",
                source_type="ai_output",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="Model output must not enter through the Notion inbox path.",
                citations=["model:candidate-task"],
            ),
            ContextEnvelope(
                ref="github:external-reference",
                kind="external_reference",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="GitHub engineering context must not enter through the Notion inbox path.",
                citations=["github:external-reference"],
            ),
            ContextEnvelope(
                ref="ctfd:manual-tag",
                kind="manual_tag",
                authority="asserted",
                source_type="ctfd",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="CTFd scoreboard context must not enter through the Notion inbox path.",
                citations=["ctfd:manual-tag"],
            ),
        ]

        result = ContextSinkValidator().validate("notion_inbox", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["notion:operator-note"])
        self.assertEqual(
            result.rejected_refs,
            ["chat:operator-note", "ctfd:manual-tag", "github:external-reference", "model:candidate-task"],
        )
        self.assertTrue(any("source_type=chat" in error for error in result.errors))
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))
        self.assertTrue(any("source_type=github" in error for error in result.errors))
        self.assertTrue(any("source_type=ctfd" in error for error in result.errors))

    def test_notion_inbox_rejects_source_markdown_path(self) -> None:
        envelope = ContextEnvelope(
            ref="notion:source-markdown-note",
            kind="operator_note",
            authority="asserted",
            source_type="notion",
            target_id="target-a",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="Quarantined Markdown must not enter through Notion inbox.",
            citations=["notion:source-markdown-note"],
            metadata={"source_file": "runtime/quarantine/markdown/docs/RAG_SRC/0x11-t10.md"},
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["notion:source-markdown-note"])
        self.assertTrue(any("source_markdown" in error for error in result.errors))

__all__ = ["NotionInboxSinkTestsPart2"]
