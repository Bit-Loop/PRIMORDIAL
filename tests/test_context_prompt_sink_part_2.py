from __future__ import annotations

from tests.test_context_prompt_sink_common import *


class ContextPromptSinkTestsPart2(ContextPromptSinkTestsBase):
    def test_prompt_sink_rejects_ai_summary_with_unsupported_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:prompt-github-source-ref",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Prompt summaries must not hide unsupported collaboration provenance.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner", "github:issue-42"],
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
            },
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:prompt-github-source-ref"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))
        self.assertTrue(any("github:issue-42" in error for error in result.errors))

    def test_prompt_sink_rejects_ai_summary_with_unresolved_note_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:prompt-fabricated-note-source-ref",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Prompt summaries must not cite fabricated operator notes as provenance.",
            citations=["note:made-up"],
            metadata={
                "source_refs": ["note:made-up"],
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
            },
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_note_refs={"note:operator-1"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:prompt-fabricated-note-source-ref"])
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))
        self.assertTrue(any("note:made-up" in error for error in result.errors))

    def test_prompt_sink_rejects_malformed_proof_records(self) -> None:
        evidence = ContextEnvelope(
            ref="evidence:scan-1",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="Observed scan result.",
            citations=["evidence:scan-1"],
        )
        malformed_evidence = ContextEnvelope(
            ref="model:evidence-shaped",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="A model-shaped record must not masquerade as evidence.",
            citations=["evidence:scan-1"],
        )
        finding = ContextEnvelope(
            ref="finding:web-1",
            kind="finding",
            authority="reviewed",
            source_type="runtime_state",
            purpose="planner",
            sink="prompt",
            content="Reviewed finding.",
            citations=["evidence:scan-1"],
        )
        malformed_finding = ContextEnvelope(
            ref="model:finding-shaped",
            kind="finding",
            authority="reviewed",
            source_type="runtime_state",
            purpose="planner",
            sink="prompt",
            content="A model-shaped record must not masquerade as a reviewed finding.",
            citations=["evidence:scan-1"],
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [evidence, malformed_evidence, finding, malformed_finding],
            known_evidence_refs={"evidence:scan-1"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:scan-1", "finding:web-1"])
        self.assertEqual(result.rejected_refs, ["model:evidence-shaped", "model:finding-shaped"])
        self.assertTrue(any("evidence:<id>" in error for error in result.errors))
        self.assertTrue(any("finding:<id>" in error for error in result.errors))

    def test_prompt_sink_rejects_proof_records_from_non_evidence_sources(self) -> None:
        evidence = ContextEnvelope(
            ref="evidence:scan-1",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="Observed scan result.",
            citations=["evidence:scan-1"],
        )
        ai_evidence = ContextEnvelope(
            ref="evidence:model-summary",
            kind="evidence",
            authority="observed",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="AI output must not enter prompts as proof even with an evidence-shaped ref.",
            citations=["evidence:scan-1"],
        )
        finding = ContextEnvelope(
            ref="finding:web-1",
            kind="finding",
            authority="reviewed",
            source_type="runtime_state",
            purpose="planner",
            sink="prompt",
            content="Reviewed finding.",
            citations=["evidence:scan-1"],
        )
        notion_finding = ContextEnvelope(
            ref="finding:notion-draft",
            kind="finding",
            authority="reviewed",
            source_type="notion",
            purpose="planner",
            sink="prompt",
            content="Notion material must not enter prompts as reviewed proof.",
            citations=["evidence:scan-1"],
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [evidence, ai_evidence, finding, notion_finding],
            known_evidence_refs={"evidence:scan-1"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:scan-1", "finding:web-1"])
        self.assertEqual(result.rejected_refs, ["evidence:model-summary", "finding:notion-draft"])
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))
        self.assertTrue(any("source_type=notion" in error for error in result.errors))

    def test_prompt_sink_rejects_generated_exports_and_raw_chat(self) -> None:
        operator_note = ContextEnvelope(
            ref="note:operator-1",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="planner",
            sink="prompt",
            content="Human-authored note.",
            citations=[],
        )
        generated_export = ContextEnvelope(
            ref="export:notion-summary",
            kind="generated_export",
            authority="derived",
            source_type="generated_export",
            purpose="planner",
            sink="prompt",
            content="Generated export must not recurse into prompt context.",
            citations=[],
        )
        export_archive = ContextEnvelope(
            ref="model:archived-export",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Archived export-origin material must not enter operational prompts.",
            citations=["note:operator-1"],
            metadata={"origin": "export_archive"},
        )
        raw_chat = ContextEnvelope(
            ref="chat:raw-1",
            kind="operator_note",
            authority="asserted",
            source_type="chat",
            purpose="planner",
            sink="prompt",
            content="Raw chat transcript must not enter operational prompts.",
            citations=[],
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [operator_note, generated_export, export_archive, raw_chat],
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["note:operator-1"])
        self.assertEqual(result.rejected_refs, ["chat:raw-1", "export:notion-summary", "model:archived-export"])
        self.assertTrue(any("generated_export" in error for error in result.errors))
        self.assertTrue(any("raw_chat_context" in error for error in result.errors))

__all__ = ["ContextPromptSinkTestsPart2"]
