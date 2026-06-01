from __future__ import annotations

from tests.test_context_assembler_common import *


class ContextAssemblerTestsPart8(ContextAssemblerTestsBase):
    def test_context_assembler_does_not_resolve_model_refs_against_note_backed_by_invalid_note(self) -> None:
        invalid_note = ContextEnvelope(
            ref="note:invalid-root-source-ref",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Invalid root note provenance must not satisfy dependent notes.",
            citations=["note:invalid-root-source-ref"],
            metadata={"source_refs": ["github:issue-42"]},
        )
        dependent_note = ContextEnvelope(
            ref="note:dependent-on-invalid-note",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Dependent notes backed by invalid notes must be omitted.",
            citations=["note:dependent-on-invalid-note", "note:invalid-root-source-ref"],
            metadata={"source_refs": ["note:invalid-root-source-ref"]},
        )
        model_summary = ContextEnvelope(
            ref="model:dependent-note-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Model summaries must not resolve against notes omitted through transitive provenance.",
            citations=["note:dependent-on-invalid-note"],
            metadata={"source_refs": ["note:dependent-on-invalid-note"]},
        )

        packet = ContextAssembler().assemble(
            [invalid_note, dependent_note, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OPERATOR_NOTES"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["note:invalid-root-source-ref"], "invalid_citation")
        self.assertEqual(omitted_refs["note:dependent-on-invalid-note"], "invalid_citation")
        self.assertEqual(omitted_refs["model:dependent-note-backed-summary"], "invalid_citation")
        self.assertNotIn("transitive provenance", packet["rendered"])

    def test_context_assembler_does_not_resolve_model_refs_against_note_backed_by_invalid_rag(self) -> None:
        invalid_rag = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "invalid-rag-for-note",
                "text": "Invalid RAG provenance must not satisfy dependent operator notes.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_refs": ["github:issue-42"],
                },
            },
            purpose="planner",
            sink="prompt",
        )
        dependent_note = ContextEnvelope(
            ref="note:dependent-on-invalid-rag",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Dependent notes backed by invalid RAG must be omitted.",
            citations=["note:dependent-on-invalid-rag", "rag:invalid-rag-for-note"],
            metadata={"source_refs": ["rag:invalid-rag-for-note"]},
        )
        model_summary = ContextEnvelope(
            ref="model:invalid-rag-backed-note-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Model summaries must not resolve against notes backed by omitted RAG.",
            citations=["note:dependent-on-invalid-rag"],
            metadata={"source_refs": ["note:dependent-on-invalid-rag"]},
        )

        packet = ContextAssembler().assemble(
            [invalid_rag, dependent_note, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["sections"]["OPERATOR_NOTES"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:invalid-rag-for-note"], "invalid_citation")
        self.assertEqual(omitted_refs["note:dependent-on-invalid-rag"], "invalid_citation")
        self.assertEqual(omitted_refs["model:invalid-rag-backed-note-summary"], "invalid_citation")
        self.assertNotIn("notes backed by omitted RAG", packet["rendered"])

    def test_context_assembler_report_writer_omits_collaboration_only_ai_summary(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="model:github-only-summary",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="report_generation",
                sink="prompt",
                content="A GitHub issue says this target fact is ready for the report.",
                citations=["github:issue-42"],
            )
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["model:github-only-summary"], "invalid_citation")
        self.assertNotIn("GitHub issue says", packet["rendered"])

    def test_context_assembler_report_writer_omits_mixed_collaboration_ai_summary(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="model:github-mixed-summary",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="report_generation",
                sink="prompt",
                content="Evidence plus a GitHub issue says this target fact is report-ready.",
                citations=["evidence:http-banner", "github:issue-42"],
            )
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["model:github-mixed-summary"], "invalid_citation")
        self.assertNotIn("GitHub issue says", packet["rendered"])

    def test_context_assembler_report_writer_omits_note_supported_ai_target_fact(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:http-banner",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="report_generation",
                sink="prompt",
                content="Observed HTTP banner reports nginx.",
                citations=["evidence:http-banner"],
            ),
            ContextEnvelope(
                ref="model:note-supported-target-fact",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="report_generation",
                sink="prompt",
                content="Operator note plus evidence says this target fact is report-ready.",
                citations=["evidence:http-banner", "note:operator-context"],
                metadata={"contains_target_fact": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["model:note-supported-target-fact"], "invalid_citation")
        self.assertNotIn("Operator note plus evidence", packet["rendered"])

    def test_context_assembler_preserves_source_refs_for_accepted_model_context(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="note:operator",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Operator note with current target context.",
                citations=["note:operator"],
            ),
            ContextEnvelope(
                ref="model:sourced-note-summary",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Model summary must keep its operator-note provenance.",
                citations=["note:operator"],
                metadata={"source_refs": ["note:operator"]},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        [model_item] = packet["sections"]["MODEL_DERIVED"]
        self.assertEqual(model_item["ref"], "model:sourced-note-summary")
        self.assertEqual(model_item["source_refs"], ["note:operator"])
        self.assertIn("source_refs=note:operator", packet["rendered"])

__all__ = [name for name in globals() if name.endswith("Part8")]
