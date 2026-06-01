from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart13(ContextSinkValidatorTestsBase):
    def test_ctfd_submission_rejects_plural_nested_recon_only_intents_for_flag_submission(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-masked-nested-recon-only-intents",
            kind="submission_result",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_submission",
            sink="ctfd_submission",
            content="Top-level solve intent must not mask nested plural recon-only flag submission intents.",
            citations=["ctfd:submission-1"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "record_type": "submission_result",
                "submission_type": "flag",
                "metadata": {"active_intents": ["recon_only"]},
            },
        )

        result = ContextSinkValidator().validate("ctfd_submission", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:submission-masked-nested-recon-only-intents"])
        self.assertTrue(any("requires ctf solve intent" in error for error in result.errors))

    def test_prompt_sink_rejects_nested_ai_summary_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-source-ref-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Nested provenance must not hide unsupported source references.",
            citations=["evidence:http-banner"],
            metadata={
                "metadata": {
                    "source_refs": ["evidence:http-banner", "github:issue-42"],
                },
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
        self.assertEqual(result.rejected_refs, ["model:nested-source-ref-summary"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_prompt_sink_rejects_rag_with_unsupported_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:prompt-unsupported-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="RAG advisory prompt context must not hide unsupported provenance.",
            citations=["rag:prompt-unsupported-source-refs"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        result = ContextSinkValidator().validate("prompt", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:prompt-unsupported-source-refs"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_prompt_sink_rejects_masked_nested_non_advisory_rag_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:prompt-masked-model-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="Top-level advisory source type must not mask nested model provenance.",
            citations=["rag:prompt-masked-model-source"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_rag_refs={"rag:prompt-masked-model-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:prompt-masked-model-source"])
        self.assertTrue(any("non_advisory_rag_source" in error for error in result.errors))
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))

    def test_prompt_sink_rejects_plural_nested_non_advisory_rag_source_types(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:prompt-plural-masked-model-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="Top-level advisory source type must not mask plural nested model provenance.",
            citations=["rag:prompt-plural-masked-model-source"],
            metadata={
                "metadata": {
                    "source_types": ["ai_output"],
                },
            },
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_rag_refs={"rag:prompt-plural-masked-model-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:prompt-plural-masked-model-source"])
        self.assertTrue(any("non_advisory_rag_source" in error for error in result.errors))
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))

    def test_prompt_sink_rejects_rag_with_unresolved_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:prompt-unresolved-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="operator_answer",
            sink="prompt",
            content="Prompt RAG context must not cite unresolved evidence provenance.",
            citations=["rag:prompt-unresolved-source-refs", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )

        result = ContextSinkValidator().validate(
            "prompt",
            [envelope],
            known_evidence_refs=set(),
            known_rag_refs={"rag:prompt-unresolved-source-refs"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:prompt-unresolved-source-refs"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_prompt_sink_rejects_masked_nested_non_evidence_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:masked-model-prompt-proof",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="planner",
            sink="prompt",
            content="Top-level evidence source type must not mask nested model provenance.",
            citations=["evidence:masked-model-prompt-proof"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )

        result = ContextSinkValidator().validate("prompt", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:masked-model-prompt-proof"])
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))

    def test_evidence_sink_rejects_rag_cited_evidence_records(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:rag-backed-service",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="evidence_review",
            sink="evidence",
            content="A RAG-only service claim must not become observed evidence.",
            citations=["rag:service-claim"],
        )

        result = ContextSinkValidator().validate("evidence", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:rag-backed-service"])
        self.assertTrue(any("rag citation" in error for error in result.errors))

    def test_evidence_sink_rejects_masked_nested_non_evidence_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:masked-model-source",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="evidence_review",
            sink="evidence",
            content="Top-level evidence source type must not mask nested model provenance.",
            citations=["evidence:masked-model-source"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )

        result = ContextSinkValidator().validate("evidence", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:masked-model-source"])
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart13"]
