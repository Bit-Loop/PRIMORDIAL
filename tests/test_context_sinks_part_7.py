from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart7(ContextSinkValidatorTestsBase):
    def test_direct_discord_notification_rejects_operator_note_with_unsupported_source_refs(self) -> None:
        note = ContextEnvelope(
            ref="note:direct-discord-unsupported-source-refs",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="discord_notification",
            sink="discord_notification",
            content="Direct Discord validation must not let operator notes hide unsupported provenance.",
            citations=["note:direct-discord-unsupported-source-refs"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        decision = validate_collaboration_sink("discord_notification", note)

        self.assertEqual(decision.action, "reject")
        self.assertIn("unsupported source_refs", decision.message)
        self.assertIn("github:issue-42", decision.message)

    def test_direct_discord_notification_rejects_rag_with_unsupported_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:direct-discord-unsupported-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="discord_notification",
            sink="discord_notification",
            content="Direct Discord validation must not let RAG hide unsupported provenance.",
            citations=["rag:direct-discord-unsupported-source-refs"],
            metadata={"labels": ["advisory"], "source_refs": ["github:issue-42"]},
        )

        decision = validate_collaboration_sink("discord_notification", envelope)

        self.assertEqual(decision.action, "reject")
        self.assertIn("unsupported source_refs", decision.message)
        self.assertIn("github:issue-42", decision.message)

    def test_discord_notification_rejects_nested_writeups_disabled_writeup(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:discord-writeups-disabled",
            kind="rag",
            authority="advisory",
            source_type="writeup",
            purpose="discord_notification",
            sink="discord_notification",
            content="Discord notifications must not publish writeup-denied material.",
            citations=["rag:discord-writeups-disabled"],
            metadata={
                "labels": ["advisory"],
                "metadata": {"writeups_allowed": False},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_rag_refs={"rag:discord-writeups-disabled"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:discord-writeups-disabled"])
        self.assertTrue(any("writeups_forbidden" in error for error in result.errors))

    def test_discord_notification_rejects_nested_truth_like_authority_on_model_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-confirmed-discord-notice",
            kind="model_summary",
            authority="derived",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested model summary authority must not notify as confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["advisory"],
                "source_refs": ["evidence:http-banner"],
                "metadata": {"authority": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:nested-confirmed-discord-notice"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_discord_notification_rejects_plural_nested_truth_like_authorities_on_model_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-confirmed-authorities-discord-notice",
            kind="model_summary",
            authority="derived",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested plural model summary authorities must not notify as confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["advisory"],
                "source_refs": ["evidence:http-banner"],
                "metadata": {"authorities": ["confirmed"]},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:nested-confirmed-authorities-discord-notice"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_discord_notification_rejects_nested_non_authority_source_authority_record(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-chat-approval-notice",
            kind="model_summary",
            authority="derived",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested chat approval metadata must not notify as an authority record.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["advisory"],
                "source_refs": ["evidence:http-banner"],
                "metadata": {"kind": "approval", "source_type": "chat"},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:nested-chat-approval-notice"])
        self.assertTrue(any("non-authority source authority record" in error for error in result.errors))

    def test_discord_notification_rejects_plural_nested_non_authority_source_authorities(self) -> None:
        envelope = ContextEnvelope(
            ref="status:nested-chat-confirmed-authorities-notice",
            kind="test_status",
            authority="asserted",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested plural chat authorities must not notify as confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["advisory"],
                "source_refs": ["evidence:http-banner"],
                "metadata": {"source_types": ["chat"], "authorities": ["confirmed"]},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["status:nested-chat-confirmed-authorities-notice"])
        self.assertTrue(any("non-authority source authority record" in error for error in result.errors))

    def test_discord_notification_rejects_plural_nested_non_authority_source_authority_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="status:nested-chat-approval-kinds-notice",
            kind="test_status",
            authority="asserted",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested plural chat authority kinds must not notify as approval records.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["advisory"],
                "source_refs": ["evidence:http-banner"],
                "metadata": {"source_types": ["chat"], "kinds": ["approval"]},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["status:nested-chat-approval-kinds-notice"])
        self.assertTrue(any("non-authority source authority record" in error for error in result.errors))

    def test_discord_notification_quarantines_nested_external_collaboration_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-github-notice",
            kind="model_summary",
            authority="derived",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="discord_notification",
            sink="discord_notification",
            content="Nested GitHub source metadata must still require an external collaboration label.",
            citations=["evidence:http-banner"],
            metadata={
                "labels": ["derived"],
                "source_refs": ["evidence:http-banner"],
                "metadata": {"source_type": "github"},
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:nested-github-notice"])
        self.assertTrue(any("requires external collaboration label" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart7"]
