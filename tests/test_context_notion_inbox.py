from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class NotionInboxSinkTests(unittest.TestCase):
    def test_notion_inbox_accepts_user_notes_and_candidate_tasks_as_proposals(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="notion:operator-note",
                kind="operator_note",
                authority="asserted",
                source_type="notion",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="User-authored note imported as an assertion.",
                citations=["notion:operator-note"],
            ),
            ContextEnvelope(
                ref="notion:candidate-task",
                kind="candidate_task",
                authority="asserted",
                source_type="notion",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="User-authored task imported as a policy-gated candidate.",
                citations=["notion:candidate-task"],
            ),
        ]

        result = ContextSinkValidator().validate("notion_inbox", envelopes)

        self.assertTrue(result.valid)
        self.assertEqual(result.accepted_refs, ["notion:candidate-task", "notion:operator-note"])
        self.assertEqual(result.rejected_refs, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])

    def test_notion_inbox_rejects_truth_like_authority_on_allowed_proposal_kinds(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="notion:authoritative-candidate-task",
                kind="candidate_task",
                authority="authoritative",
                source_type="notion",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="A Notion candidate task must remain a policy-gated proposal.",
                citations=["notion:authoritative-candidate-task"],
            ),
            ContextEnvelope(
                ref="notion:observed-operator-note",
                kind="operator_note",
                authority="observed",
                source_type="notion",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="A Notion operator note must remain an assertion, not observed evidence.",
                citations=["notion:observed-operator-note"],
            ),
            ContextEnvelope(
                ref="notion:confirmed-hypothesis",
                kind="hypothesis",
                authority="confirmed",
                source_type="notion",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="A Notion hypothesis must not carry confirmed target-truth authority.",
                citations=["notion:confirmed-hypothesis"],
            ),
        ]

        result = ContextSinkValidator().validate("notion_inbox", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            [
                "notion:authoritative-candidate-task",
                "notion:confirmed-hypothesis",
                "notion:observed-operator-note",
            ],
        )
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_notion_inbox_rejects_authority_mutation_edits(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="notion:evidence-edit",
                kind="evidence",
                authority="observed",
                source_type="notion",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="A Notion edit must not create observed evidence directly.",
                citations=["notion:evidence-edit"],
                metadata={"creates_evidence": True},
            ),
            ContextEnvelope(
                ref="notion:approval-edit",
                kind="approval",
                authority="asserted",
                source_type="notion",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="A Notion edit must not approve credential validation.",
                citations=["notion:approval-edit"],
                metadata={"creates_approval": True},
            ),
            ContextEnvelope(
                ref="notion:scope-edit",
                kind="scope",
                authority="asserted",
                source_type="notion",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="A Notion edit must not expand target scope.",
                citations=["notion:scope-edit"],
                metadata={"expands_scope": True},
            ),
            ContextEnvelope(
                ref="notion:intent-edit",
                kind="operator_intent",
                authority="asserted",
                source_type="notion",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="A Notion edit must not change Operator Intent.",
                citations=["notion:intent-edit"],
                metadata={"changes_operator_intent": True},
            ),
            ContextEnvelope(
                ref="notion:confirmed-finding",
                kind="finding",
                authority="reviewed",
                source_type="notion",
                target_id="target-a",
                purpose="notion_inbox",
                sink="notion_inbox",
                content="A Notion edit must not confirm a finding directly.",
                citations=["notion:confirmed-finding"],
                metadata={"confirms_finding": True},
            ),
        ]

        result = ContextSinkValidator().validate("notion_inbox", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(
            result.rejected_refs,
            [
                "notion:approval-edit",
                "notion:confirmed-finding",
                "notion:evidence-edit",
                "notion:intent-edit",
                "notion:scope-edit",
            ],
        )
        for phrase in ("evidence", "approval", "scope", "Operator Intent", "confirmed finding"):
            self.assertTrue(any(phrase in error for error in result.errors), phrase)

    def test_notion_inbox_rejects_human_readable_authority_mutation_flags(self) -> None:
        envelope = ContextEnvelope(
            ref="notion:display-scope-edit",
            kind="candidate_task",
            authority="asserted",
            source_type="notion",
            target_id="target-a",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="A Notion candidate task must not expand target scope.",
            citations=["notion:display-scope-edit"],
            metadata={"Changes scope": True},
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["notion:display-scope-edit"])
        self.assertTrue(any("scope" in error for error in result.errors))

    def test_notion_inbox_rejects_finding_draft_that_marks_confirmed_status(self) -> None:
        envelope = ContextEnvelope(
            ref="notion:confirmed-finding-draft",
            kind="finding_draft_delta",
            authority="asserted",
            source_type="notion",
            target_id="target-a",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="A Notion draft edit must not confirm a finding directly.",
            citations=["notion:confirmed-finding-draft"],
            metadata={"Finding status": "Confirmed"},
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["notion:confirmed-finding-draft"])
        self.assertTrue(any("confirmed finding" in error for error in result.errors))

    def test_notion_inbox_quarantines_user_edit_to_primordial_owned_block(self) -> None:
        envelope = ContextEnvelope(
            ref="notion:runtime-state-block-edit",
            kind="operator_note",
            authority="asserted",
            source_type="notion",
            target_id="target-a",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="User edit to a Primordial-owned runtime state block.",
            citations=["notion:runtime-state-block-edit"],
            metadata={
                "block_owner": "primordial",
                "edit_source": "user",
                "section": "Runtime State",
                "local_entity_type": "runtime_state",
            },
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, [])
        self.assertEqual(result.quarantined_refs, ["notion:runtime-state-block-edit"])
        self.assertTrue(any("manual review" in error for error in result.errors))
        self.assertTrue(any("Primordial-owned" in error for error in result.errors))

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


if __name__ == "__main__":
    unittest.main()
