from __future__ import annotations

from tests.test_context_citations_common import *


class ContextCitationValidatorTestsPart2(ContextCitationValidatorTestsBase):
    def test_advisory_claim_requires_rag_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:advisory-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="operator_answer",
            sink="report",
            content="Advisory methodology says to retry routing checks.",
            citations=["note:operator-1"],
            metadata={"advisory_claim": True},
        )

        result = CitationValidator().validate([envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["model:advisory-summary"])
        self.assertTrue(any("requires rag:<chunk_id>" in error for error in result.errors))
        self.assertTrue(any("note:operator-1" in error for error in result.errors))

    def test_mixed_target_fact_and_advisory_claim_requires_both_citation_types(self) -> None:
        envelope = ContextEnvelope(
            ref="model:mixed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="The target reports nginx; advisory methodology says to retry routing checks.",
            citations=["evidence:http-banner"],
            metadata={"contains_target_fact": True, "advisory_claim": True},
        )

        result = CitationValidator().validate([envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:mixed-summary"])
        self.assertTrue(any("requires rag:<chunk_id>" in error for error in result.errors))
        self.assertTrue(any("evidence:http-banner" in error for error in result.errors))

    def test_confirmed_finding_requires_evidence_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="finding:confirmed-rag-only",
            kind="finding",
            authority="confirmed",
            source_type="runtime_state",
            target_id="target-a",
            purpose="finding_generation",
            sink="finding",
            content="Confirmed findings must be supported by observed evidence.",
            citations=["rag:version-hint"],
        )

        result = CitationValidator().validate([envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["finding:confirmed-rag-only"])
        self.assertTrue(any("requires evidence:<id>" in error for error in result.errors))
        self.assertTrue(any("rag:version-hint" in error for error in result.errors))

    def test_human_readable_advisory_marker_requires_rag_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:display-advisory-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="operator_answer",
            sink="report",
            content="Advisory methodology says to retry routing checks.",
            citations=["note:operator-1"],
            metadata={"Advisory claim": True},
        )

        result = CitationValidator().validate([envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["model:display-advisory-summary"])
        self.assertTrue(any("requires rag:<chunk_id>" in error for error in result.errors))
        self.assertTrue(any("note:operator-1" in error for error in result.errors))

    def test_string_encoded_advisory_marker_requires_rag_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:string-advisory-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="operator_answer",
            sink="report",
            content="Advisory methodology says to retry routing checks.",
            citations=["note:operator-1"],
            metadata={"Advisory claim": "yes"},
        )

        result = CitationValidator().validate([envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["model:string-advisory-summary"])
        self.assertTrue(any("requires rag:<chunk_id>" in error for error in result.errors))
        self.assertTrue(any("note:operator-1" in error for error in result.errors))

    def test_advisory_claim_accepts_rag_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:advisory-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="operator_answer",
            sink="report",
            content="Advisory methodology says to retry routing checks.",
            citations=["note:operator-1", "rag:routing-method"],
            metadata={"advisory_claim": True},
        )

        result = CitationValidator().validate([envelope])

        self.assertTrue(result.valid)
        self.assertEqual(result.accepted_refs, ["model:advisory-summary"])
        self.assertEqual(result.errors, [])

    def test_advisory_claim_rejects_mixed_non_rag_citation_support(self) -> None:
        envelopes = [
            self._advisory_claim("model:note-and-rag-advisory", ["note:operator-1", "rag:routing-method"]),
            self._advisory_claim("model:github-mixed-advisory", ["rag:routing-method", "github:issue-1"]),
            self._advisory_claim("model:notion-mixed-advisory", ["rag:routing-method", "notion:note-1"]),
            self._advisory_claim("model:ctfd-mixed-advisory", ["rag:routing-method", "ctfd:challenge-1"]),
            self._advisory_claim("model:model-mixed-advisory", ["rag:routing-method", "model:summary"]),
            self._advisory_claim("model:chat-mixed-advisory", ["rag:routing-method", "chat:operator-context"]),
        ]

        result = CitationValidator().validate(envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["model:note-and-rag-advisory"])
        self.assertEqual(
            result.rejected_refs,
            [
                "model:chat-mixed-advisory",
                "model:ctfd-mixed-advisory",
                "model:github-mixed-advisory",
                "model:model-mixed-advisory",
                "model:notion-mixed-advisory",
            ],
        )
        self.assertTrue(any("non-rag citation support" in error for error in result.errors))

__all__ = ["ContextCitationValidatorTestsPart2"]
