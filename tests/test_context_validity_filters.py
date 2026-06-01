from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope


class ContextValidityFilterTests(unittest.TestCase):
    def test_valid_for_limits_context_to_matching_purpose_or_role(self) -> None:
        envelopes = [
            self._note(
                "note:planner-only",
                "Planner-only operator note must not enter report context.",
                valid_for=["planner"],
            ),
            self._note(
                "note:report",
                "Report writer may use this operator note.",
                valid_for=["report_writer"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(
            [item["ref"] for item in packet["sections"]["OPERATOR_NOTES"]],
            ["note:report"],
        )
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["note:planner-only"], "not_valid_for_context")
        self.assertNotIn("Planner-only operator note", packet["rendered"])

    def test_invalid_for_blocks_matching_role_purpose_or_sink(self) -> None:
        envelopes = [
            self._rag(
                "rag:role-blocked",
                "Role-blocked RAG must not reach the methodology advisor.",
                invalid_for=["methodology_advisor"],
            ),
            self._note(
                "note:purpose-blocked",
                "Planner-blocked note must not enter planner packets.",
                invalid_for=["planner"],
            ),
            self._note(
                "note:sink-blocked",
                "Prompt-blocked note must not enter prompt packets.",
                invalid_for=["prompt"],
            ),
            self._rag(
                "rag:allowed",
                "Allowed advisory context remains available.",
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(
            [item["ref"] for item in packet["sections"]["RAG_ADVISORY"]],
            ["rag:allowed"],
        )
        self.assertEqual(packet["sections"]["OPERATOR_NOTES"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:role-blocked"], "invalid_for_context")
        self.assertEqual(omitted_refs["note:purpose-blocked"], "invalid_for_context")
        self.assertEqual(omitted_refs["note:sink-blocked"], "invalid_for_context")
        self.assertNotIn("Role-blocked RAG", packet["rendered"])
        self.assertNotIn("Planner-blocked note", packet["rendered"])
        self.assertNotIn("Prompt-blocked note", packet["rendered"])

    def test_invalid_for_normalizes_human_readable_context_names(self) -> None:
        envelopes = [
            self._rag(
                "rag:notion-export-blocked",
                "Human-readable exclusions must still block operational export packets.",
                invalid_for=["Notion export"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="notion_export",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:notion-export-blocked"], "invalid_for_context")
        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertNotIn("Human-readable exclusions", packet["rendered"])

    def test_valid_for_does_not_match_source_sink_when_assembling_prompt(self) -> None:
        export_only = ContextEnvelope(
            ref="note:export-only",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="notion_export",
            sink="notion_export",
            content="Export-only note must not enter planner prompts.",
            valid_for=["notion_export"],
            citations=["note:export-only"],
        )

        packet = ContextAssembler().assemble(
            [export_only],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OPERATOR_NOTES"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["note:export-only"], "not_valid_for_context")
        self.assertNotIn("Export-only note", packet["rendered"])

    def test_invalid_for_rag_cannot_support_model_advisory_claim(self) -> None:
        envelopes = [
            self._rag(
                "rag:allowed",
                "Allowed RAG may support an advisory model summary.",
            ),
            self._rag(
                "rag:role-blocked",
                "Role-blocked RAG must not support rendered model summaries.",
                invalid_for=["methodology_advisor"],
            ),
            self._model_advisory("model:allowed", ["rag:allowed"]),
            self._model_advisory("model:role-blocked", ["rag:role-blocked"]),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:allowed"])
        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:allowed"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:role-blocked"], "invalid_for_context")
        self.assertEqual(omitted_refs["model:role-blocked"], "invalid_citation")
        self.assertNotIn("model:role-blocked", packet["rendered"])

    def test_invalid_for_evidence_cannot_support_model_target_fact(self) -> None:
        envelopes = [
            self._evidence(
                "evidence:allowed",
                "Allowed evidence may support a target-fact model summary.",
            ),
            self._evidence(
                "evidence:role-blocked",
                "Role-blocked evidence must not support rendered model summaries.",
                invalid_for=["methodology_advisor"],
            ),
            self._model_target_fact("model:allowed-fact", ["evidence:allowed"]),
            self._model_target_fact("model:role-blocked-fact", ["evidence:role-blocked"]),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["OBSERVED_EVIDENCE"]], ["evidence:allowed"])
        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:allowed-fact"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:role-blocked"], "invalid_for_context")
        self.assertEqual(omitted_refs["model:role-blocked-fact"], "invalid_citation")
        self.assertNotIn("model:role-blocked-fact", packet["rendered"])

    def _evidence(
        self,
        ref: str,
        content: str,
        *,
        valid_for: list[str] | None = None,
        invalid_for: list[str] | None = None,
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content=content,
            valid_for=valid_for or [],
            invalid_for=invalid_for or [],
            citations=[ref],
        )

    def _note(
        self,
        ref: str,
        content: str,
        *,
        valid_for: list[str] | None = None,
        invalid_for: list[str] | None = None,
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content=content,
            valid_for=valid_for or [],
            invalid_for=invalid_for or [],
            citations=[ref],
        )

    def _rag(
        self,
        ref: str,
        content: str,
        *,
        valid_for: list[str] | None = None,
        invalid_for: list[str] | None = None,
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="methodology_hint",
            sink="prompt",
            content=content,
            valid_for=valid_for or [],
            invalid_for=invalid_for or [],
            citations=[ref],
        )

    def _model_advisory(self, ref: str, citations: list[str]) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content=f"{ref} advisory summary.",
            citations=citations,
            metadata={"advisory_claim": True},
        )

    def _model_target_fact(self, ref: str, citations: list[str]) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content=f"{ref} target fact summary.",
            citations=citations,
            metadata={"target_fact": True},
        )


if __name__ == "__main__":
    unittest.main()
