from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart5(ContextSinkValidatorTestsBase):
    def test_prompt_sink_rejects_model_refs_against_nested_retrieval_disabled_rag(self) -> None:
        disabled_rag = ContextEnvelope(
            ref="rag:nested-disabled-prompt-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="Retrieval-disabled RAG must not satisfy prompt model context.",
            citations=["rag:nested-disabled-prompt-source"],
            metadata={"metadata": {"operational_retrieval_allowed": False}},
        )
        model_summary = ContextEnvelope(
            ref="model:nested-disabled-rag-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against retrieval-disabled RAG.",
            citations=["rag:nested-disabled-prompt-source"],
            metadata={"source_refs": ["rag:nested-disabled-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [disabled_rag, model_summary],
            known_rag_refs={"rag:nested-disabled-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["model:nested-disabled-rag-backed", "rag:nested-disabled-prompt-source"],
        )
        self.assertTrue(any("operational_retrieval_allowed=false" in error for error in result.errors))
        self.assertTrue(any("unresolved rag citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_list_valued_retrieval_disabled_rag(self) -> None:
        disabled_rag = ContextEnvelope(
            ref="rag:list-disabled-prompt-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="List-valued retrieval-disabled RAG must not satisfy prompt model context.",
            citations=["rag:list-disabled-prompt-source"],
            metadata={"metadata": {"operational_retrieval_allowed": [True, False]}},
        )
        model_summary = ContextEnvelope(
            ref="model:list-disabled-rag-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against list-valued retrieval-disabled RAG.",
            citations=["rag:list-disabled-prompt-source"],
            metadata={"source_refs": ["rag:list-disabled-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [disabled_rag, model_summary],
            known_rag_refs={"rag:list-disabled-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["model:list-disabled-rag-backed", "rag:list-disabled-prompt-source"],
        )
        self.assertTrue(any("operational_retrieval_allowed=false" in error for error in result.errors))
        self.assertTrue(any("unresolved rag citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_nested_writeups_disabled_rag(self) -> None:
        disabled_writeup = ContextEnvelope(
            ref="rag:nested-writeups-disabled-prompt-source",
            kind="rag",
            authority="advisory",
            source_type="writeup",
            purpose="ctf_solver_context",
            sink="prompt",
            content="Nested writeup deny metadata must not satisfy prompt model context.",
            citations=["rag:nested-writeups-disabled-prompt-source"],
            metadata={"metadata": {"writeups_allowed": False}},
        )
        model_summary = ContextEnvelope(
            ref="model:nested-writeup-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="ctf_solver_context",
            sink="prompt",
            content="Model output must not resolve against writeup-disabled RAG.",
            citations=["rag:nested-writeups-disabled-prompt-source"],
            metadata={"source_refs": ["rag:nested-writeups-disabled-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [disabled_writeup, model_summary],
            known_rag_refs={"rag:nested-writeups-disabled-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["model:nested-writeup-backed", "rag:nested-writeups-disabled-prompt-source"],
        )
        self.assertTrue(any("writeups_forbidden" in error for error in result.errors))
        self.assertTrue(any("unresolved rag citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_masked_non_advisory_rag_source(self) -> None:
        invalid_rag = ContextEnvelope(
            ref="rag:masked-model-prompt-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="Top-level advisory source type must not mask nested model provenance.",
            citations=["rag:masked-model-prompt-source"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )
        model_summary = ContextEnvelope(
            ref="model:masked-rag-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against masked non-advisory RAG sources.",
            citations=["rag:masked-model-prompt-source"],
            metadata={"source_refs": ["rag:masked-model-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [invalid_rag, model_summary],
            known_rag_refs={"rag:masked-model-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:masked-rag-backed", "rag:masked-model-prompt-source"])
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))
        self.assertTrue(any("unresolved rag citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_rejected_evidence_source_refs(self) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:bad-prompt-source",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="Evidence with unsupported source refs must not satisfy prompt model context.",
            citations=["evidence:bad-prompt-source"],
            metadata={"source_refs": ["github:issue-42"]},
        )
        model_summary = ContextEnvelope(
            ref="model:bad-evidence-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against rejected evidence source refs.",
            citations=["evidence:bad-prompt-source"],
            metadata={"source_refs": ["evidence:bad-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [invalid_evidence, model_summary],
            known_evidence_refs={"evidence:bad-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:bad-prompt-source", "model:bad-evidence-backed"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_prompt_sink_rejects_model_refs_against_non_proof_evidence_source(self) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:github-prompt-source",
            kind="evidence",
            authority="observed",
            source_type="github",
            purpose="planner",
            sink="prompt",
            content="GitHub engineering context must not satisfy prompt evidence refs.",
            citations=["evidence:github-prompt-source"],
        )
        model_summary = ContextEnvelope(
            ref="model:github-evidence-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against non-proof evidence sources.",
            citations=["evidence:github-prompt-source"],
            metadata={"source_refs": ["evidence:github-prompt-source"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [invalid_evidence, model_summary],
            known_evidence_refs={"evidence:github-prompt-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:github-prompt-source", "model:github-evidence-backed"])
        self.assertTrue(any("source_type=github" in error for error in result.errors))
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart5"]
