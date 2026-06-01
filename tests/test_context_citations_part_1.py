from __future__ import annotations

from tests.test_context_citations_common import *


class ContextCitationValidatorTestsPart1(ContextCitationValidatorTestsBase):
    def test_target_factual_claim_requires_evidence_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:target-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="target_state_answer",
            sink="report",
            content="The target is running Apache 2.4.49.",
            citations=["rag:apache-249"],
            metadata={"contains_target_fact": True},
        )

        result = CitationValidator().validate([envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["model:target-summary"])
        self.assertTrue(any("requires evidence:<id>" in error for error in result.errors))
        self.assertTrue(any("rag:apache-249" in error for error in result.errors))

    def test_human_readable_target_fact_marker_requires_evidence_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:display-target-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="target_state_answer",
            sink="report",
            content="The target is running Apache 2.4.49.",
            citations=["rag:apache-249"],
            metadata={"Target factual claim": True},
        )

        result = CitationValidator().validate([envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["model:display-target-summary"])
        self.assertTrue(any("requires evidence:<id>" in error for error in result.errors))
        self.assertTrue(any("rag:apache-249" in error for error in result.errors))

    def test_string_encoded_target_fact_marker_requires_evidence_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:string-target-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="target_state_answer",
            sink="report",
            content="The target is running Apache 2.4.49.",
            citations=["rag:apache-249"],
            metadata={"Target factual claim": "true"},
        )

        result = CitationValidator().validate([envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["model:string-target-summary"])
        self.assertTrue(any("requires evidence:<id>" in error for error in result.errors))
        self.assertTrue(any("rag:apache-249" in error for error in result.errors))

    def test_rejects_fabricated_evidence_citation_when_known_refs_are_supplied(self) -> None:
        envelope = ContextEnvelope(
            ref="model:target-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="target_state_answer",
            sink="report",
            content="The target is running Apache 2.4.49.",
            citations=["evidence:made-up"],
            metadata={"contains_target_fact": True},
        )

        result = CitationValidator(known_evidence_refs={"evidence:observed-banner"}).validate([envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["model:target-summary"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))
        self.assertTrue(any("evidence:made-up" in error for error in result.errors))

    def test_human_readable_known_evidence_ref_resolves_canonical_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:target-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="target_state_answer",
            sink="report",
            content="The target is running Apache 2.4.49.",
            citations=["evidence:observed-banner"],
            metadata={"contains_target_fact": True},
        )

        result = CitationValidator(known_evidence_refs={"Evidence:observed-banner"}).validate([envelope])

        self.assertTrue(result.valid)
        self.assertEqual(result.accepted_refs, ["model:target-summary"])
        self.assertEqual(result.rejected_refs, [])

    def test_target_factual_claim_rejects_placeholder_evidence_citation_without_known_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:target-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="target_state_answer",
            sink="report",
            content="The target is running Apache 2.4.49.",
            citations=["evidence:unknown"],
            metadata={"contains_target_fact": True},
        )

        result = CitationValidator().validate([envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["model:target-summary"])
        self.assertTrue(any("placeholder evidence citation" in error for error in result.errors))
        self.assertTrue(any("evidence:unknown" in error for error in result.errors))

    def test_target_factual_claim_rejects_mixed_non_evidence_citation_support(self) -> None:
        envelopes = [
            self._target_fact("model:evidence-only", ["evidence:observed-banner"]),
            self._target_fact("model:rag-mixed", ["evidence:observed-banner", "rag:version-hint"]),
            self._target_fact("model:model-mixed", ["evidence:observed-banner", "model:summary"]),
            self._target_fact("model:github-mixed", ["evidence:observed-banner", "github:issue-1"]),
            self._target_fact("model:notion-mixed", ["evidence:observed-banner", "notion:note-1"]),
            self._target_fact("model:ctfd-mixed", ["evidence:observed-banner", "ctfd:challenge-1"]),
            self._target_fact(
                "model:advisory-rag-mixed",
                ["evidence:observed-banner", "rag:routing-method"],
                advisory_claim=True,
            ),
        ]

        result = CitationValidator().validate(envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["model:advisory-rag-mixed", "model:evidence-only"])
        self.assertEqual(
            result.rejected_refs,
            [
                "model:ctfd-mixed",
                "model:github-mixed",
                "model:model-mixed",
                "model:notion-mixed",
                "model:rag-mixed",
            ],
        )
        self.assertTrue(any("non-evidence citation support" in error for error in result.errors))

    def test_rejects_unindexed_rag_citation_when_known_refs_are_supplied(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:made-up",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="operator_answer",
            sink="prompt",
            content="Advisory context must come from an indexed RAG chunk.",
            citations=["rag:made-up"],
        )

        result = CitationValidator(known_rag_refs={"rag:indexed-method"}).validate([envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["rag:made-up"])
        self.assertTrue(any("unresolved rag citation" in error for error in result.errors))
        self.assertTrue(any("rag:made-up" in error for error in result.errors))

    def test_rejects_rag_envelope_with_mismatched_indexed_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:unindexed-method",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="operator_answer",
            sink="prompt",
            content="RAG advisory envelopes must not cite a different indexed chunk as support.",
            citations=["rag:indexed-method"],
        )

        result = CitationValidator(known_rag_refs={"rag:indexed-method"}).validate([envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["rag:unindexed-method"])
        self.assertTrue(any("must cite its own rag ref" in error for error in result.errors))

    def test_rejects_placeholder_rag_refs_without_known_index(self) -> None:
        rag_envelope = ContextEnvelope(
            ref="rag:unknown",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="operator_answer",
            sink="report",
            content="RAG advisory context must have an explicit indexed identity.",
            citations=["rag:unknown"],
        )
        advisory_summary = ContextEnvelope(
            ref="model:advisory-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="operator_answer",
            sink="report",
            content="Advisory methodology says to retry routing checks.",
            citations=["rag:unknown"],
            metadata={"advisory_claim": True},
        )

        result = CitationValidator().validate([rag_envelope, advisory_summary])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["model:advisory-summary", "rag:unknown"])
        self.assertTrue(any("placeholder rag citation" in error for error in result.errors))
        self.assertTrue(any("rag:unknown" in error for error in result.errors))

    def test_rejects_null_placeholder_rag_refs_without_known_index(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:None",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="operator_answer",
                sink="report",
                content="RAG advisory context must not use None as an indexed identity.",
                citations=["rag:None"],
            ),
            ContextEnvelope(
                ref="model:null-advisory-summary",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                purpose="operator_answer",
                sink="report",
                content="Advisory summaries must not cite null placeholder RAG refs.",
                citations=["rag:null"],
                metadata={"advisory_claim": True},
            ),
        ]

        result = CitationValidator().validate(envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["model:null-advisory-summary", "rag:None"])
        self.assertTrue(any("placeholder rag citation" in error for error in result.errors))
        self.assertTrue(any("rag:None" in error for error in result.errors))
        self.assertTrue(any("rag:null" in error for error in result.errors))

__all__ = ["ContextCitationValidatorTestsPart1"]
