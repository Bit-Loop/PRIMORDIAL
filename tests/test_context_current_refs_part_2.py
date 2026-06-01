from __future__ import annotations

from tests.test_context_current_refs_common import *


class ContextCurrentRefsTestsPart2(ContextCurrentRefsTestsBase):
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

    def test_current_refs_exclude_legacy_source_markdown_paths(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:legacy-rag-src",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Legacy advisory Markdown must not support evidence current refs.",
                citations=["evidence:legacy-rag-src"],
                metadata={"source_file": "docs/RAG_SRC/0x11-t10.md"},
            ),
            ContextEnvelope(
                ref="rag:legacy-rag-src",
                kind="rag",
                authority="advisory",
                source_type="validated_external",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Legacy advisory Markdown must not support RAG current refs.",
                citations=["rag:legacy-rag-src"],
                metadata={"source_file": "docs/RAG_SRC/0x11-t10.md"},
            ),
            ContextEnvelope(
                ref="note:legacy-rag-src",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Legacy advisory Markdown must not support note current refs.",
                citations=["note:legacy-rag-src"],
                metadata={"source_file": "docs/RAG_SRC/0x11-t10.md"},
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
        self.assertEqual(
            prompt_context_omission_reason(envelopes[0], purpose="planner", role="methodology_advisor"),
            "source_markdown",
        )

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

__all__ = ["ContextCurrentRefsTestsPart2"]
