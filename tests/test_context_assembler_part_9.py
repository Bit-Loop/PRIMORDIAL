from __future__ import annotations

from tests.test_context_assembler_common import *


class ContextAssemblerTestsPart9(ContextAssemblerTestsBase):
    def test_context_assembler_omits_model_context_with_placeholder_source_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:placeholder-note-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Placeholder source citations must not render as model context.",
            citations=["note:null"],
        )

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["model:placeholder-note-summary"], "invalid_citation")
        self.assertNotIn("Placeholder source citations", packet["rendered"])

    def test_context_assembler_rejects_ai_output_disguised_as_operator_note(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="note:model-generated",
                kind="operator_note",
                authority="asserted",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="AI output must not enter the operator note lane.",
                citations=["note:model-generated"],
            ),
            ContextEnvelope(
                ref="model:note-backed",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Derived context must not cite a model-generated note.",
                citations=["note:model-generated"],
                metadata={"source_refs": ["note:model-generated"]},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OPERATOR_NOTES"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["note:model-generated"], "non_operator_note_source")
        self.assertEqual(omitted_refs["model:note-backed"], "invalid_citation")
        self.assertNotIn("AI output must not enter", packet["rendered"])

    def test_context_assembler_rejects_model_target_fact_backed_by_sensitive_evidence(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:secret",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Sensitive evidence must not enter prompt context.",
                citations=["evidence:secret"],
                metadata={"contains_secret": True},
            ),
            ContextEnvelope(
                ref="model:secret-backed-target-fact",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Derived target fact must not cite omitted sensitive evidence.",
                citations=["evidence:secret"],
                metadata={"contains_target_fact": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OBSERVED_EVIDENCE"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:secret"], "sensitive_material")
        self.assertEqual(omitted_refs["model:secret-backed-target-fact"], "invalid_citation")
        self.assertNotIn("Sensitive evidence must not enter", packet["rendered"])
        self.assertNotIn("Derived target fact must not cite", packet["rendered"])

    def test_context_assembler_rejects_model_advisory_backed_by_target_fact_rag(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:target-fact",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="RAG target fact material must not enter prompt context.",
                citations=["rag:target-fact"],
                metadata={"contains_target_fact": True},
            ),
            ContextEnvelope(
                ref="model:target-fact-rag-advisory",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Derived advisory must not cite omitted target-fact RAG.",
                citations=["rag:target-fact"],
                metadata={"advisory_claim": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:target-fact"], "target_fact_rag")
        self.assertEqual(omitted_refs["model:target-fact-rag-advisory"], "invalid_citation")
        self.assertNotIn("RAG target fact material", packet["rendered"])
        self.assertNotIn("Derived advisory must not cite", packet["rendered"])

__all__ = [name for name in globals() if name.endswith("Part9")]
