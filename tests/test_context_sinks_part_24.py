from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart24(ContextSinkValidatorTestsBase):
    def test_rag_index_rejects_model_and_chat_generated_material(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="model:summary-to-rag",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                purpose="cleanup",
                sink="rag_index",
                content="AI-derived summaries must not become active operational RAG.",
                citations=["evidence:current"],
            ),
            ContextEnvelope(
                ref="chat:operator-context",
                kind="operator_note",
                authority="asserted",
                source_type="chat",
                purpose="cleanup",
                sink="rag_index",
                content="Chat context is advisory conversation, not active operational RAG.",
                citations=["note:operator"],
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["chat:operator-context", "model:summary-to-rag"])
        self.assertTrue(any("generated model or chat material" in error for error in result.errors))

    def test_rag_index_rejects_plural_nested_generated_model_source_types(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-ai-output-source-types",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested plural source type metadata must not let generated model output become active RAG.",
            citations=["rag:nested-ai-output-source-types"],
            metadata={"metadata": {"source_types": ["ai_output"]}},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-ai-output-source-types"])
        self.assertTrue(any("generated model or chat material" in error for error in result.errors))

    def test_rag_index_rejects_evidence_and_authority_lane_material(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:scan-result-to-rag",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="cleanup",
                sink="rag_index",
                content="Observed scan results belong in evidence, not active advisory RAG.",
                citations=["evidence:scan-result-to-rag"],
            ),
            ContextEnvelope(
                ref="state:scope-to-rag",
                kind="authority",
                authority="authoritative",
                source_type="runtime_state",
                purpose="cleanup",
                sink="rag_index",
                content="Runtime authority state must not become active advisory RAG.",
                citations=["policy_decision:scope"],
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:scan-result-to-rag", "state:scope-to-rag"])
        self.assertTrue(any("evidence or authority lane material" in error for error in result.errors))

    def test_rag_index_rejects_plural_nested_evidence_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-evidence-kinds",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested plural kind metadata must not let evidence lane material become active RAG.",
            citations=["rag:nested-evidence-kinds"],
            metadata={"metadata": {"kinds": ["evidence"]}},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-evidence-kinds"])
        self.assertTrue(any("evidence or authority lane material" in error for error in result.errors))

    def test_rag_index_rejects_reviewed_findings_and_operator_notes(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="finding:reviewed-to-rag",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                purpose="cleanup",
                sink="rag_index",
                content="Reviewed findings belong in the finding lane, not active advisory RAG.",
                citations=["evidence:banner"],
            ),
            ContextEnvelope(
                ref="note:operator-to-rag",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                purpose="cleanup",
                sink="rag_index",
                content="Operator assertions belong in the notes lane, not active advisory RAG.",
                citations=["note:operator-to-rag"],
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["finding:reviewed-to-rag", "note:operator-to-rag"])
        self.assertTrue(any("target context lane material" in error for error in result.errors))

    def test_rag_index_rejects_plural_nested_target_context_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-finding-kinds",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested plural kind metadata must not let target findings become active RAG.",
            citations=["rag:nested-finding-kinds"],
            metadata={"metadata": {"kinds": ["finding"]}},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-finding-kinds"])
        self.assertTrue(any("target context lane material" in error for error in result.errors))

    def test_rag_index_rejects_derived_planning_state(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="hypothesis:service-path-to-rag",
                kind="hypothesis",
                authority="asserted",
                source_type="manual_artifact",
                purpose="cleanup",
                sink="rag_index",
                content="Unverified hypotheses belong in derived planning state, not active advisory RAG.",
                citations=["note:operator-hypothesis"],
            ),
            ContextEnvelope(
                ref="task:candidate-to-rag",
                kind="candidate_task",
                authority="asserted",
                source_type="manual_artifact",
                purpose="cleanup",
                sink="rag_index",
                content="Candidate tasks must remain policy-gated planning state, not retrievable RAG.",
                citations=["policy_decision:pending"],
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["hypothesis:service-path-to-rag", "task:candidate-to-rag"])
        self.assertTrue(any("derived planning state" in error for error in result.errors))

    def test_rag_index_rejects_plural_nested_derived_planning_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-hypothesis-kinds",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested plural kind metadata must not let derived planning state become active RAG.",
            citations=["rag:nested-hypothesis-kinds"],
            metadata={"metadata": {"kinds": ["hypothesis"]}},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-hypothesis-kinds"])
        self.assertTrue(any("derived planning state" in error for error in result.errors))

    def test_rag_index_rejects_collaboration_reference_lanes(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:methodology",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="methodology_hint",
                sink="rag_index",
                content="General methodology remains valid advisory RAG material.",
                citations=["rag:methodology"],
            ),
            ContextEnvelope(
                ref="github:issue-to-rag",
                kind="github_ref",
                authority="asserted",
                source_type="github",
                purpose="cleanup",
                sink="rag_index",
                content="GitHub issue prose is an engineering ledger projection, not active operational RAG.",
                citations=["github:issue-to-rag"],
            ),
            ContextEnvelope(
                ref="notion:page-to-rag",
                kind="notion_ref",
                authority="asserted",
                source_type="notion",
                purpose="cleanup",
                sink="rag_index",
                content="Notion page prose is collaborative projection material, not active operational RAG.",
                citations=["notion:page-to-rag"],
            ),
            ContextEnvelope(
                ref="ctfd:challenge-to-rag",
                kind="ctfd_ref",
                authority="asserted",
                source_type="ctfd",
                purpose="cleanup",
                sink="rag_index",
                content="CTFd challenge metadata is scoreboard projection, not active operational RAG.",
                citations=["ctfd:challenge-to-rag"],
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:methodology"])
        self.assertEqual(
            result.rejected_refs,
            ["ctfd:challenge-to-rag", "github:issue-to-rag", "notion:page-to-rag"],
        )
        self.assertTrue(any("collaboration reference lane material" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart24"]
