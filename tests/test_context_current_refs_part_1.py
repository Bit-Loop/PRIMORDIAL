from __future__ import annotations

from tests.test_context_current_refs_common import *


class ContextCurrentRefsTestsPart1(ContextCurrentRefsTestsBase):
    def test_current_refs_filter_to_prompt_safe_current_context(self) -> None:
        envelopes = self._current_ref_filter_envelopes()
        context = {
            "target_id": "target-a",
            "active_generation_id": "generation:2",
            "purpose": "planner",
            "role": "methodology_advisor",
        }

        self.assertEqual(current_evidence_refs(envelopes, **context), {"evidence:current"})
        self.assertEqual(current_rag_refs(envelopes, **context), {"rag:current"})
        self.assertEqual(current_note_refs(envelopes, **context), {"note:current"})

    def _current_ref_filter_envelopes(self) -> list[ContextEnvelope]:
        return [
            ContextEnvelope(
                ref="evidence:current",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Current observed evidence.",
                citations=["evidence:current"],
            ),
            ContextEnvelope(
                ref="evidence:export",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Generated export evidence must not support current context.",
                citations=["evidence:export"],
                metadata={"source_file": "findings/notion/target-a/notion-export.md"},
            ),
            ContextEnvelope(
                ref="rag:current",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Current advisory RAG.",
                citations=["rag:current"],
            ),
            ContextEnvelope(
                ref="rag:stale",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                target_id="target-a",
                active_generation_id="generation:1",
                purpose="planner",
                sink="prompt",
                content="Stale advisory RAG.",
                citations=["rag:stale"],
            ),
            ContextEnvelope(
                ref="note:current",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Current operator note.",
                citations=["note:current"],
            ),
            ContextEnvelope(
                ref="note:wrong-target",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                target_id="target-b",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Wrong target note.",
                citations=["note:wrong-target"],
            ),
        ]

    def test_current_evidence_refs_exclude_role_sensitive_material(self) -> None:
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
                content="Sensitive evidence must not support derived context.",
                citations=["evidence:secret"],
                metadata={"contains_secret": True},
            ),
        ]

        refs = current_evidence_refs(
            envelopes,
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            role="methodology_advisor",
        )

        self.assertEqual(refs, set())

    def test_current_rag_refs_exclude_target_fact_material(self) -> None:
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
                content="RAG target facts must not support derived prompt context.",
                citations=["rag:target-fact"],
                metadata={"contains_target_fact": True},
            ),
        ]

        refs = current_rag_refs(
            envelopes,
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            role="methodology_advisor",
        )

        self.assertEqual(refs, set())

    def test_current_rag_refs_exclude_generated_export_source_url(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:generated-export-url",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Generated export URL material must not support derived prompt context.",
                citations=["rag:generated-export-url"],
                metadata={"source_url": "https://example.invalid/findings/notion/target-a/notion-export.md"},
            ),
        ]

        refs = current_rag_refs(
            envelopes,
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            role="methodology_advisor",
        )

        self.assertEqual(refs, set())
        self.assertEqual(
            prompt_context_omission_reason(envelopes[0], purpose="planner", role="methodology_advisor"),
            "generated_export",
        )

    def test_current_rag_refs_exclude_nested_operational_retrieval_disabled(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:nested-retrieval-disabled",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Nested retrieval-disabled RAG must not support derived prompt context.",
                citations=["rag:nested-retrieval-disabled"],
                metadata={"metadata": {"operational_retrieval_allowed": False}},
            ),
        ]

        refs = current_rag_refs(
            envelopes,
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            role="methodology_advisor",
        )

        self.assertEqual(refs, set())
        self.assertEqual(
            prompt_context_omission_reason(envelopes[0], purpose="planner", role="methodology_advisor"),
            "operational_retrieval_disabled",
        )

    def test_current_rag_refs_exclude_masked_nested_non_advisory_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:masked-model-current",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Top-level advisory source type must not mask nested model provenance.",
            citations=["rag:masked-model-current"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )

        refs = current_rag_refs(
            [envelope],
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            role="methodology_advisor",
        )

        self.assertEqual(refs, set())

__all__ = ["ContextCurrentRefsTestsPart1"]
