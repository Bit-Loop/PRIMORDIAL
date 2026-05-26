from __future__ import annotations

import unittest

from primordial.core.context.current_refs import (
    current_evidence_refs,
    current_note_refs,
    current_rag_refs,
    prompt_context_omission_reason,
)
from primordial.core.context.envelopes import ContextEnvelope


class ContextCurrentRefsTests(unittest.TestCase):
    def test_current_refs_filter_to_prompt_safe_current_context(self) -> None:
        envelopes = [
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

        context = {
            "target_id": "target-a",
            "active_generation_id": "generation:2",
            "purpose": "planner",
            "role": "methodology_advisor",
        }

        self.assertEqual(current_evidence_refs(envelopes, **context), {"evidence:current"})
        self.assertEqual(current_rag_refs(envelopes, **context), {"rag:current"})
        self.assertEqual(current_note_refs(envelopes, **context), {"note:current"})

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

    def test_current_rag_refs_exclude_plural_nested_non_advisory_source_types(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:plural-masked-model-current",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Top-level advisory source type must not mask plural nested model provenance.",
            citations=["rag:plural-masked-model-current"],
            metadata={
                "metadata": {
                    "source_types": ["ai_output"],
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

    def test_current_refs_exclude_unsupported_source_refs_metadata(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:unsupported-source-ref",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Observed evidence with unsupported provenance must not support current context.",
                citations=["evidence:unsupported-source-ref"],
                metadata={"source_refs": ["github:issue-42"]},
            ),
            ContextEnvelope(
                ref="rag:unsupported-source-ref",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="RAG with unsupported provenance must not support current context.",
                citations=["rag:unsupported-source-ref"],
                metadata={"metadata": {"source_refs": ["github:issue-42"]}},
            ),
            ContextEnvelope(
                ref="note:unsupported-source-ref",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Operator note with unsupported provenance must not support current context.",
                citations=["note:unsupported-source-ref"],
                metadata={"source_refs": ["github:issue-42"]},
            ),
        ]

        context = {
            "target_id": "target-a",
            "active_generation_id": "generation:2",
            "purpose": "planner",
            "role": "methodology_advisor",
        }

        self.assertEqual(current_evidence_refs(envelopes, **context), set())
        self.assertEqual(current_rag_refs(envelopes, **context), set())
        self.assertEqual(current_note_refs(envelopes, **context), set())

    def test_current_evidence_refs_exclude_masked_nested_non_evidence_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:masked-model-current",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Top-level evidence source type must not mask nested model provenance.",
            citations=["evidence:masked-model-current"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )

        refs = current_evidence_refs(
            [envelope],
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            role="methodology_advisor",
        )

        self.assertEqual(refs, set())

    def test_prompt_context_omission_reason_centralizes_prompt_safety(self) -> None:
        valid = ContextEnvelope(
            ref="note:current",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="planner",
            sink="prompt",
            content="Current operator note.",
            citations=["note:current"],
        )
        wrong_sink = ContextEnvelope(
            ref="note:wrong-sink",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="planner",
            sink="report",
            content="Report-only note.",
            citations=["note:wrong-sink"],
        )
        raw_chat = ContextEnvelope(
            ref="note:chat",
            kind="operator_note",
            authority="asserted",
            source_type="chat",
            purpose="planner",
            sink="prompt",
            content="Raw chat must not enter prompt context.",
            citations=["note:chat"],
        )
        nested_raw_chat = ContextEnvelope(
            ref="rag:nested-chat",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="planner",
            sink="prompt",
            content="Top-level methodology source type must not mask nested chat provenance.",
            citations=["rag:nested-chat"],
            metadata={"metadata": {"source_type": "chat"}},
        )
        invalid_for_role = ContextEnvelope(
            ref="note:invalid-role",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="planner",
            sink="prompt",
            content="Invalid for this role.",
            citations=["note:invalid-role"],
            invalid_for=("methodology_advisor",),
        )
        not_valid_for_purpose = ContextEnvelope(
            ref="note:not-valid-purpose",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="planner",
            sink="prompt",
            content="Only valid for a different purpose.",
            citations=["note:not-valid-purpose"],
            valid_for=("report_generation",),
        )

        context = {"purpose": "planner", "role": "methodology_advisor"}

        self.assertEqual(prompt_context_omission_reason(valid, **context), "")
        self.assertEqual(prompt_context_omission_reason(wrong_sink, **context), "sink_mismatch")
        self.assertEqual(prompt_context_omission_reason(raw_chat, **context), "raw_chat_context")
        self.assertEqual(prompt_context_omission_reason(nested_raw_chat, **context), "raw_chat_context")
        self.assertEqual(prompt_context_omission_reason(invalid_for_role, **context), "invalid_for_context")
        self.assertEqual(prompt_context_omission_reason(not_valid_for_purpose, **context), "not_valid_for_context")


if __name__ == "__main__":
    unittest.main()
