from __future__ import annotations

from tests.test_context_assembler_common import *


class ContextAssemblerTestsPart7(ContextAssemblerTestsBase):
    def test_context_assembler_omits_reviewed_finding_with_operator_note_proof_support(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:banner",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="report_generation",
                sink="prompt",
                content="Observed HTTP banner reports nginx.",
                citations=["evidence:banner"],
            ),
            ContextEnvelope(
                ref="finding:note-supported-service",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="report_generation",
                sink="prompt",
                content="Reviewed finding must not be supported by operator notes.",
                citations=["evidence:banner", "note:operator-context"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["OBSERVED_EVIDENCE"]], ["evidence:banner"])
        self.assertEqual(packet["sections"]["REVIEWED_FINDINGS"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["finding:note-supported-service"], "invalid_citation")
        self.assertNotIn("Reviewed finding must not be supported by operator notes.", packet["rendered"])

    def test_context_assembler_omits_evidence_with_unsupported_source_refs_metadata(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:github-provenance-service",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="report_generation",
                sink="prompt",
                content="Observed evidence must not hide collaboration provenance.",
                citations=["evidence:github-provenance-service"],
                metadata={
                    "source_refs": [
                        "evidence:github-provenance-service",
                        "github:issue-42",
                    ]
                },
            )
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OBSERVED_EVIDENCE"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:github-provenance-service"], "invalid_citation")
        self.assertNotIn("Observed evidence must not hide collaboration provenance.", packet["rendered"])

    def test_context_assembler_report_writer_omits_rag_only_ai_target_facts(self) -> None:
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
                ref="model:rag-only-target-fact",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="report_generation",
                sink="prompt",
                content="The target is running Apache 2.4.49.",
                citations=["rag:apache-249"],
                metadata={"contains_target_fact": True},
            ),
            ContextEnvelope(
                ref="model:evidence-backed-target-fact",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="report_generation",
                sink="prompt",
                content="The target reports nginx in the HTTP banner.",
                citations=["evidence:http-banner"],
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

        model_refs = [item["ref"] for item in packet["sections"]["MODEL_DERIVED"]]
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}

        self.assertEqual(model_refs, ["model:evidence-backed-target-fact"])
        self.assertEqual(omitted_refs["model:rag-only-target-fact"], "invalid_citation")
        self.assertNotIn("Apache 2.4.49", packet["rendered"])
        self.assertIn("nginx", packet["rendered"])

    def test_context_assembler_omits_operator_note_with_unsupported_source_refs(self) -> None:
        note = ContextEnvelope(
            ref="note:unsupported-source-ref",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Operator note provenance must not hide collaboration refs.",
            citations=["note:unsupported-source-ref"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        packet = ContextAssembler().assemble(
            [note],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OPERATOR_NOTES"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["note:unsupported-source-ref"], "invalid_citation")
        self.assertNotIn("hide collaboration refs", packet["rendered"])

    def test_context_assembler_omits_operator_note_with_unresolved_source_refs(self) -> None:
        note = ContextEnvelope(
            ref="note:unresolved-source-ref",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Operator note provenance must not cite unresolved evidence.",
            citations=["note:unresolved-source-ref", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )

        packet = ContextAssembler().assemble(
            [note],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OPERATOR_NOTES"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["note:unresolved-source-ref"], "invalid_citation")
        self.assertNotIn("unresolved evidence", packet["rendered"])

    def test_context_assembler_does_not_resolve_model_refs_against_invalid_operator_note(self) -> None:
        note = ContextEnvelope(
            ref="note:invalid-source-ref",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Invalid operator-note provenance must not satisfy downstream source refs.",
            citations=["note:invalid-source-ref"],
            metadata={"source_refs": ["github:issue-42"]},
        )
        model_summary = ContextEnvelope(
            ref="model:invalid-note-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Model summary must not be accepted when backed by omitted notes.",
            citations=["note:invalid-source-ref"],
            metadata={"source_refs": ["note:invalid-source-ref"]},
        )

        packet = ContextAssembler().assemble(
            [note, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OPERATOR_NOTES"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["note:invalid-source-ref"], "invalid_citation")
        self.assertEqual(omitted_refs["model:invalid-note-backed-summary"], "invalid_citation")
        self.assertNotIn("backed by omitted notes", packet["rendered"])

__all__ = [name for name in globals() if name.endswith("Part7")]
