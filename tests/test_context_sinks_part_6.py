from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart6(ContextSinkValidatorTestsBase):
    def test_prompt_sink_rejects_model_refs_against_masked_non_proof_evidence_source(self) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:masked-model-prompt-source",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="Top-level evidence source type must not mask nested model provenance.",
            citations=["evidence:masked-model-prompt-source"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )
        model_summary = ContextEnvelope(
            ref="model:masked-evidence-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against masked non-proof evidence sources.",
            citations=["evidence:masked-model-prompt-source"],
            metadata={"source_refs": ["evidence:masked-model-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [invalid_evidence, model_summary],
            known_evidence_refs={"evidence:masked-model-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:masked-model-prompt-source", "model:masked-evidence-backed"])
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_invalid_evidence_authority(self) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:advisory-prompt-source",
            kind="evidence",
            authority="advisory",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="Advisory evidence authority must not satisfy prompt model context.",
            citations=["evidence:advisory-prompt-source"],
        )
        model_summary = ContextEnvelope(
            ref="model:advisory-evidence-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against invalid evidence authority.",
            citations=["evidence:advisory-prompt-source"],
            metadata={"source_refs": ["evidence:advisory-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [invalid_evidence, model_summary],
            known_evidence_refs={"evidence:advisory-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:advisory-prompt-source", "model:advisory-evidence-backed"])
        self.assertTrue(any("authority=advisory" in error for error in result.errors))
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_rag_cited_evidence(self) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:rag-backed-prompt-source",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="RAG advisory material must not satisfy prompt evidence refs.",
            citations=["rag:service-claim"],
        )
        model_summary = ContextEnvelope(
            ref="model:rag-backed-evidence-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against RAG-cited evidence.",
            citations=["evidence:rag-backed-prompt-source"],
            metadata={"source_refs": ["evidence:rag-backed-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [invalid_evidence, model_summary],
            known_evidence_refs={"evidence:rag-backed-prompt-source"},
            known_rag_refs={"rag:service-claim"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["evidence:rag-backed-prompt-source", "model:rag-backed-evidence-summary"],
        )
        self.assertTrue(any("non-evidence citation support" in error for error in result.errors))
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_generated_export_evidence(self) -> None:
        generated_export_evidence = ContextEnvelope(
            ref="evidence:generated-export-prompt-source",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="Generated export evidence must not satisfy prompt model context.",
            citations=["evidence:generated-export-prompt-source"],
            metadata={"origin": "generated_export"},
        )
        model_summary = ContextEnvelope(
            ref="model:generated-export-evidence-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against generated export evidence.",
            citations=["evidence:generated-export-prompt-source"],
            metadata={"source_refs": ["evidence:generated-export-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [generated_export_evidence, model_summary],
            known_evidence_refs={"evidence:generated-export-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["evidence:generated-export-prompt-source", "model:generated-export-evidence-backed"],
        )
        self.assertTrue(any("generated_export" in error for error in result.errors))
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_prompt_sink_rejects_finding_with_unsupported_source_refs(self) -> None:
        finding = ContextEnvelope(
            ref="finding:bad-prompt-source",
            kind="finding",
            authority="reviewed",
            source_type="runtime_state",
            purpose="planner",
            sink="prompt",
            content="Reviewed findings with unsupported source refs must not enter prompts.",
            citations=["evidence:http-banner"],
            metadata={"source_refs": ["evidence:http-banner", "github:issue-42"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [finding],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["finding:bad-prompt-source"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_discord_notification_rejects_ai_output_disguised_as_operator_note(self) -> None:
        operator_note = ContextEnvelope(
            ref="note:operator-1",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="discord_notification",
            sink="discord_notification",
            content="Human-authored operator note may be included in operator notification context.",
            citations=["note:operator-1"],
        )
        model_note = ContextEnvelope(
            ref="note:model-generated",
            kind="operator_note",
            authority="asserted",
            source_type="ai_output",
            purpose="discord_notification",
            sink="discord_notification",
            content="AI output must not enter the operator-note lane for notifications.",
            citations=["note:model-generated"],
            metadata={"labels": ["advisory"]},
        )

        result = ContextSinkValidator().validate("discord_notification", [operator_note, model_note])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["note:operator-1"])
        self.assertEqual(result.rejected_refs, ["note:model-generated"])
        self.assertTrue(any("non_operator_note_source" in error for error in result.errors))

    def test_discord_notification_rejects_model_refs_against_rejected_operator_note(self) -> None:
        note = ContextEnvelope(
            ref="note:bad-discord-provenance",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="discord_notification",
            sink="discord_notification",
            content="Discord note provenance must not cite unresolved evidence.",
            citations=["note:bad-discord-provenance", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )
        model_summary = ContextEnvelope(
            ref="model:bad-discord-note-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="discord_notification",
            sink="discord_notification",
            content="Discord model output must not resolve against a rejected operator note.",
            citations=["note:bad-discord-provenance"],
            metadata={"labels": ["advisory"], "source_refs": ["note:bad-discord-provenance"]},
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [note, model_summary],
            known_evidence_refs=set(),
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:bad-discord-note-backed", "note:bad-discord-provenance"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart6"]
