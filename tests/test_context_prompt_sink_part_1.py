from __future__ import annotations

from tests.test_context_prompt_sink_common import *


class ContextPromptSinkTestsPart1(ContextPromptSinkTestsBase):
    def test_prompt_sink_rejects_uncited_rag_context(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:uncited-prompt-methodology",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="Prompt-bound RAG material must preserve its rag citation.",
            citations=[],
        )

        result = ContextSinkValidator().validate("prompt", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:uncited-prompt-methodology"])
        self.assertTrue(any("must cite its own rag ref" in error for error in result.errors))

    def test_prompt_sink_rejects_rag_from_non_advisory_sources(self) -> None:
        methodology = ContextEnvelope(
            ref="rag:methodology",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="Methodology material may enter prompt context as advisory RAG.",
            citations=["rag:methodology"],
        )
        ai_rag = ContextEnvelope(
            ref="rag:model-generated",
            kind="rag",
            authority="advisory",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not be laundered into prompt context as RAG.",
            citations=["rag:model-generated"],
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [methodology, ai_rag],
            known_rag_refs={"rag:methodology", "rag:model-generated"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:methodology"])
        self.assertEqual(result.rejected_refs, ["rag:model-generated"])
        self.assertTrue(any("non_advisory_rag_source" in error for error in result.errors))
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))

    def test_prompt_sink_rejects_target_fact_marked_rag(self) -> None:
        methodology = ContextEnvelope(
            ref="rag:methodology",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Methodology advisory material may enter prompt context.",
            citations=["rag:methodology"],
        )
        target_fact_rag = ContextEnvelope(
            ref="rag:target-fact",
            kind="rag",
            authority="advisory",
            source_type="vuln_intel",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="RAG material claims target-a is running a vulnerable service.",
            citations=["rag:target-fact", "evidence:observed-service"],
            metadata={
                "advisory_claim": True,
                "contains_target_fact": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
            },
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [methodology, target_fact_rag],
            known_evidence_refs={"evidence:observed-service"},
            known_rag_refs={"rag:methodology", "rag:target-fact"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:methodology"])
        self.assertEqual(result.rejected_refs, ["rag:target-fact"])
        self.assertTrue(any("target fact" in error for error in result.errors))

    def test_prompt_sink_rejects_wrong_target_and_stale_proof_records(self) -> None:
        current_evidence = ContextEnvelope(
            ref="evidence:current-scan",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Current target evidence may enter prompt context.",
            citations=["evidence:current-scan"],
            metadata={"current_target_id": "target-a", "current_active_generation_id": "generation:2"},
        )
        wrong_target_evidence = ContextEnvelope(
            ref="evidence:wrong-target-scan",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-b",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Wrong-target evidence must not enter prompt context.",
            citations=["evidence:wrong-target-scan"],
            metadata={"current_target_id": "target-a", "current_active_generation_id": "generation:2"},
        )
        stale_finding = ContextEnvelope(
            ref="finding:stale-service",
            kind="finding",
            authority="reviewed",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:1",
            purpose="planner",
            sink="prompt",
            content="Stale-generation finding must not enter prompt context as current truth.",
            citations=["evidence:current-scan"],
            metadata={"current_target_id": "target-a", "current_active_generation_id": "generation:2"},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [current_evidence, wrong_target_evidence, stale_finding],
            known_evidence_refs={"evidence:current-scan", "evidence:wrong-target-scan"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:current-scan"])
        self.assertEqual(result.rejected_refs, ["evidence:wrong-target-scan", "finding:stale-service"])
        self.assertTrue(any("wrong_target" in error for error in result.errors))
        self.assertTrue(any("stale_generation" in error for error in result.errors))

    def test_prompt_sink_rejects_wrong_target_and_stale_model_target_facts(self) -> None:
        result = ContextSinkValidator().validate(
            "prompt",
            self._model_target_fact_envelopes(),
            known_evidence_refs={"evidence:current-scan"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["model:current-target-fact"])
        self.assertEqual(
            result.rejected_refs,
            ["model:missing-generation-fact", "model:stale-target-fact", "model:wrong-target-fact"],
        )
        self.assertTrue(any("wrong_target" in error for error in result.errors))
        self.assertTrue(any("stale_generation" in error for error in result.errors))
        self.assertTrue(any("missing_generation_binding" in error for error in result.errors))

    def _model_target_fact_envelopes(self) -> list[ContextEnvelope]:
        current_summary = ContextEnvelope(
            ref="model:current-target-fact",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Model target facts may enter prompts only when current-bound and evidence-cited.",
            citations=["evidence:current-scan"],
            metadata={
                "contains_target_fact": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
            },
        )
        wrong_target_summary = ContextEnvelope(
            ref="model:wrong-target-fact",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-b",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Wrong-target model target facts must not enter prompt context.",
            citations=["evidence:current-scan"],
            metadata={
                "contains_target_fact": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
            },
        )
        stale_summary = ContextEnvelope(
            ref="model:stale-target-fact",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:1",
            purpose="planner",
            sink="prompt",
            content="Stale model target facts must not enter prompt context as current truth.",
            citations=["evidence:current-scan"],
            metadata={
                "contains_target_fact": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
            },
        )
        unbound_summary = ContextEnvelope(
            ref="model:missing-generation-fact",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="planner",
            sink="prompt",
            content="Generationless model target facts must not enter current prompt context.",
            citations=["evidence:current-scan"],
            metadata={
                "contains_target_fact": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
            },
        )
        return [current_summary, wrong_target_summary, stale_summary, unbound_summary]

__all__ = ["ContextPromptSinkTestsPart1"]
