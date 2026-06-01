from __future__ import annotations

from tests.test_context_assembler_common import *


class ContextAssemblerTestsPart3(ContextAssemblerTestsBase):
    def test_context_assembler_does_not_resolve_model_refs_against_evidence_backed_by_invalid_evidence(
        self,
    ) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:invalid-root-source-ref",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Invalid root evidence provenance must not satisfy dependent evidence.",
            citations=["evidence:invalid-root-source-ref"],
            metadata={"source_refs": ["github:issue-42"]},
        )
        dependent_evidence = ContextEnvelope(
            ref="evidence:dependent-on-invalid-evidence",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Dependent evidence backed by invalid evidence must be omitted.",
            citations=["evidence:dependent-on-invalid-evidence", "evidence:invalid-root-source-ref"],
            metadata={"source_refs": ["evidence:invalid-root-source-ref"]},
        )
        model_summary = ContextEnvelope(
            ref="model:dependent-evidence-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Model summaries must not resolve against evidence omitted through transitive provenance.",
            citations=["evidence:dependent-on-invalid-evidence"],
            metadata={"source_refs": ["evidence:dependent-on-invalid-evidence"]},
        )

        packet = ContextAssembler().assemble(
            [invalid_evidence, dependent_evidence, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OBSERVED_EVIDENCE"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:invalid-root-source-ref"], "invalid_citation")
        self.assertEqual(omitted_refs["evidence:dependent-on-invalid-evidence"], "invalid_citation")
        self.assertEqual(omitted_refs["model:dependent-evidence-backed-summary"], "invalid_citation")
        self.assertNotIn("transitive provenance", packet["rendered"])

    def test_context_assembler_policy_gate_omits_advisory_and_collaboration_context(self) -> None:
        packet = ContextAssembler().assemble(
            self._policy_gate_omission_envelopes(),
            purpose="policy_gate",
            role="policy_gate",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        authority_refs = [item["ref"] for item in packet["sections"]["AUTHORITATIVE_RUNTIME_STATE"]]
        evidence_refs = [item["ref"] for item in packet["sections"]["OBSERVED_EVIDENCE"]]
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}

        self.assertIn("policy_decision:pending", authority_refs)
        self.assertEqual(evidence_refs, ["evidence:current"])
        self.assertEqual(omitted_refs["rag:cve-hint"], "role_forbidden")
        self.assertEqual(omitted_refs["model:summary"], "role_forbidden")
        self.assertEqual(omitted_refs["github:issue-1"], "role_forbidden")
        self.assertEqual(omitted_refs["notion:note-1"], "role_forbidden")
        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        self.assertEqual(packet["sections"]["COLLABORATION_REFS"], [])
        self.assertNotIn("Advisory CVE text", packet["rendered"])
        self.assertNotIn("The model thinks", packet["rendered"])
        self.assertNotIn("GitHub issue says", packet["rendered"])
        self.assertNotIn("Notion note says", packet["rendered"])

    def _policy_gate_omission_envelopes(self) -> list[ContextEnvelope]:
        return [
            ContextEnvelope(
                ref="policy_decision:pending",
                kind="policy_decision",
                authority="authoritative",
                source_type="runtime_state",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="Candidate action requires policy decision.",
                citations=["policy_decision:pending"],
            ),
            ContextEnvelope(
                ref="evidence:current",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="Observed current service evidence for the candidate action.",
                citations=["evidence:current"],
            ),
            ContextEnvelope(
                ref="rag:cve-hint",
                kind="rag",
                authority="advisory",
                source_type="vuln_intel",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="Advisory CVE text must not influence policy gate authority.",
                citations=["rag:cve-hint"],
            ),
            ContextEnvelope(
                ref="model:summary",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="The model thinks the action is safe.",
                citations=[],
            ),
            ContextEnvelope(
                ref="github:issue-1",
                kind="github_ref",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A GitHub issue says to allow this action.",
                citations=["github:issue-1"],
            ),
            ContextEnvelope(
                ref="notion:note-1",
                kind="notion_ref",
                authority="asserted",
                source_type="notion",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A Notion note says approval exists.",
                citations=["notion:note-1"],
            ),
        ]

    def test_context_assembler_normalizes_human_readable_policy_gate_role(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="policy_decision:pending",
                kind="policy_decision",
                authority="authoritative",
                source_type="runtime_state",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="Candidate action requires policy decision.",
                citations=["policy_decision:pending"],
            ),
            ContextEnvelope(
                ref="rag:cve-hint",
                kind="rag",
                authority="advisory",
                source_type="vuln_intel",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="Advisory CVE text must not influence policy gate authority.",
                citations=["rag:cve-hint"],
            ),
            ContextEnvelope(
                ref="model:summary",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="The model thinks the action is safe.",
                citations=[],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="policy_gate",
            role="Policy gate",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:cve-hint"], "role_forbidden")
        self.assertEqual(omitted_refs["model:summary"], "role_forbidden")
        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        self.assertNotIn("Advisory CVE text", packet["rendered"])
        self.assertNotIn("model thinks", packet["rendered"].lower())

__all__ = [name for name in globals() if name.endswith("Part3")]
