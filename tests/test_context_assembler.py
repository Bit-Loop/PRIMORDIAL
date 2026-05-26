from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope


class ContextAssemblerTests(unittest.TestCase):
    def test_context_assembler_filters_wrong_target_and_labels_stale_generation(self) -> None:
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
                content="tcp/443 is open on the current active IP.",
                citations=["evidence:current"],
            ),
            ContextEnvelope(
                ref="evidence:wrong-target",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-b",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="tcp/80 is open on another target.",
                citations=["evidence:wrong-target"],
            ),
            ContextEnvelope(
                ref="evidence:stale",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                active_generation_id="generation:1",
                purpose="planner",
                sink="prompt",
                content="tcp/80 was open on the old active IP.",
                citations=["evidence:stale"],
            ),
            ContextEnvelope(
                ref="rag:method-1",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="If TCP evidence is sparse, verify routing and active IP generation.",
                citations=["rag:method-1"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        current_refs = [item["ref"] for item in packet["sections"]["OBSERVED_EVIDENCE"]]
        rag_refs = [item["ref"] for item in packet["sections"]["RAG_ADVISORY"]]
        historical_refs = [item["ref"] for item in packet["historical_context"]]
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}

        self.assertEqual(current_refs, ["evidence:current"])
        self.assertEqual(rag_refs, ["rag:method-1"])
        self.assertEqual(historical_refs, ["evidence:stale"])
        self.assertEqual(omitted_refs["evidence:wrong-target"], "wrong_target")
        self.assertIn("AUTHORITATIVE_RUNTIME_STATE", packet["rendered"])
        self.assertIn("OBSERVED_EVIDENCE", packet["rendered"])
        self.assertIn("RAG_ADVISORY", packet["rendered"])
        self.assertNotIn("tcp/80 is open on another target", packet["rendered"])

    def test_context_assembler_omits_unbound_current_evidence(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:no-target",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Targetless evidence must not enter current target context.",
                citations=["evidence:no-target"],
            ),
            ContextEnvelope(
                ref="evidence:no-generation",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                purpose="planner",
                sink="prompt",
                content="Generationless evidence must not enter current target context.",
                citations=["evidence:no-generation"],
            ),
            ContextEnvelope(
                ref="rag:global-method",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="planner",
                sink="prompt",
                content="Global methodology can still advise without target proof.",
                citations=["rag:global-method"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OBSERVED_EVIDENCE"], [])
        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:global-method"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:no-target"], "missing_target_binding")
        self.assertEqual(omitted_refs["evidence:no-generation"], "missing_generation_binding")
        self.assertNotIn("Targetless evidence", packet["rendered"])
        self.assertNotIn("Generationless evidence", packet["rendered"])

    def test_context_assembler_omits_placeholder_rag_refs(self) -> None:
        placeholder = ContextEnvelope.from_rag_chunk(
            {
                "text": "RAG payload without chunk identity must not become citable context.",
                "metadata": {"source_type": "methodology_doc"},
            },
            purpose="planner",
            sink="prompt",
        )
        indexed = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "indexed-method",
                "text": "Indexed methodology can enter advisory context.",
                "metadata": {"source_type": "methodology_doc"},
            },
            purpose="planner",
            sink="prompt",
        )

        packet = ContextAssembler().assemble(
            [placeholder, indexed],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:indexed-method"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:unknown"], "placeholder_rag_ref")
        self.assertNotIn("without chunk identity", packet["rendered"])
        self.assertIn("Indexed methodology", packet["rendered"])

    def test_context_assembler_omits_rag_with_unsupported_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "unsupported-source-ref-advisory",
                "text": "RAG advisory must not hide collaboration provenance.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_refs": ["github:issue-42"],
                },
            },
            purpose="planner",
            sink="prompt",
        )

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:unsupported-source-ref-advisory"], "invalid_citation")
        self.assertNotIn("hide collaboration provenance", packet["rendered"])

    def test_context_assembler_omits_rag_with_unresolved_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "unresolved-source-ref-advisory",
                "text": "RAG advisory must not cite unresolved evidence provenance.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_refs": ["evidence:missing-banner"],
                },
            },
            purpose="planner",
            sink="prompt",
        )
        envelope.citations.append("evidence:missing-banner")

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:unresolved-source-ref-advisory"], "invalid_citation")
        self.assertNotIn("unresolved evidence provenance", packet["rendered"])

    def test_context_assembler_does_not_resolve_model_refs_against_invalid_rag(self) -> None:
        invalid_rag = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "invalid-rag-source-ref",
                "text": "Invalid RAG provenance must not satisfy downstream source refs.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_refs": ["github:issue-42"],
                },
            },
            purpose="planner",
            sink="prompt",
        )
        model_summary = ContextEnvelope(
            ref="model:invalid-rag-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model summary must not be accepted when backed by omitted RAG.",
            citations=["rag:invalid-rag-source-ref"],
            metadata={"source_refs": ["rag:invalid-rag-source-ref"]},
        )

        packet = ContextAssembler().assemble(
            [invalid_rag, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:invalid-rag-source-ref"], "invalid_citation")
        self.assertEqual(omitted_refs["model:invalid-rag-backed-summary"], "invalid_citation")
        self.assertNotIn("Model summary must not be accepted", packet["rendered"])

    def test_context_assembler_does_not_resolve_model_refs_against_unresolved_rag(self) -> None:
        invalid_rag = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "unresolved-rag-source-ref",
                "text": "Unresolved RAG provenance must not satisfy downstream source refs.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_refs": ["evidence:missing-banner"],
                },
            },
            purpose="planner",
            sink="prompt",
        )
        invalid_rag.citations.append("evidence:missing-banner")
        model_summary = ContextEnvelope(
            ref="model:unresolved-rag-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model summary must not be accepted when backed by unresolved RAG.",
            citations=["rag:unresolved-rag-source-ref"],
            metadata={"source_refs": ["rag:unresolved-rag-source-ref"]},
        )

        packet = ContextAssembler().assemble(
            [invalid_rag, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:unresolved-rag-source-ref"], "invalid_citation")
        self.assertEqual(omitted_refs["model:unresolved-rag-backed-summary"], "invalid_citation")
        self.assertNotIn("backed by unresolved RAG", packet["rendered"])

    def test_context_assembler_does_not_resolve_model_refs_against_rag_backed_by_invalid_rag(self) -> None:
        invalid_rag = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "invalid-root-rag-source-ref",
                "text": "Invalid root RAG provenance must not satisfy dependent RAG.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_refs": ["github:issue-42"],
                },
            },
            purpose="planner",
            sink="prompt",
        )
        dependent_rag = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "dependent-on-invalid-rag",
                "text": "Dependent RAG backed by invalid RAG must be omitted.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_refs": ["rag:invalid-root-rag-source-ref"],
                },
            },
            purpose="planner",
            sink="prompt",
        )
        dependent_rag.citations.append("rag:invalid-root-rag-source-ref")
        model_summary = ContextEnvelope(
            ref="model:dependent-rag-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model summaries must not resolve against RAG omitted through transitive provenance.",
            citations=["rag:dependent-on-invalid-rag"],
            metadata={"source_refs": ["rag:dependent-on-invalid-rag"]},
        )

        packet = ContextAssembler().assemble(
            [invalid_rag, dependent_rag, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:invalid-root-rag-source-ref"], "invalid_citation")
        self.assertEqual(omitted_refs["rag:dependent-on-invalid-rag"], "invalid_citation")
        self.assertEqual(omitted_refs["model:dependent-rag-backed-summary"], "invalid_citation")
        self.assertNotIn("transitive provenance", packet["rendered"])

    def test_context_assembler_does_not_resolve_model_refs_against_generated_export_rag(self) -> None:
        generated_export_rag = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "generated-export-source-ref",
                "citation_id": "rag:generated-export-source-ref",
                "text": "Generated export advisory must not satisfy downstream source refs.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "source_url": "https://example.invalid/findings/notion/rag.htb/notion-export.md",
                },
            },
            purpose="planner",
            sink="prompt",
        )
        model_summary = ContextEnvelope(
            ref="model:generated-export-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model summary must not be accepted when backed by generated export RAG.",
            citations=["rag:generated-export-source-ref"],
            metadata={"source_refs": ["rag:generated-export-source-ref"]},
        )

        packet = ContextAssembler().assemble(
            [generated_export_rag, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:generated-export-source-ref"], "generated_export")
        self.assertEqual(omitted_refs["model:generated-export-backed-summary"], "invalid_citation")
        self.assertNotIn("backed by generated export RAG", packet["rendered"])

    def test_context_assembler_does_not_resolve_model_refs_against_invalid_evidence(self) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:invalid-source-ref",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Invalid evidence provenance must not satisfy downstream source refs.",
            citations=["evidence:invalid-source-ref"],
            metadata={"source_refs": ["evidence:invalid-source-ref", "github:issue-42"]},
        )
        model_summary = ContextEnvelope(
            ref="model:invalid-evidence-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Model summary must not be accepted when backed by omitted evidence.",
            citations=["evidence:invalid-source-ref"],
            metadata={"source_refs": ["evidence:invalid-source-ref"]},
        )

        packet = ContextAssembler().assemble(
            [invalid_evidence, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OBSERVED_EVIDENCE"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:invalid-source-ref"], "invalid_citation")
        self.assertEqual(omitted_refs["model:invalid-evidence-backed-summary"], "invalid_citation")
        self.assertNotIn("backed by omitted evidence", packet["rendered"])

    def test_context_assembler_does_not_resolve_model_refs_against_unresolved_evidence(self) -> None:
        invalid_evidence = ContextEnvelope(
            ref="evidence:unresolved-source-ref",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Unresolved evidence provenance must not satisfy downstream source refs.",
            citations=["evidence:unresolved-source-ref", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )
        model_summary = ContextEnvelope(
            ref="model:unresolved-evidence-backed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Model summary must not be accepted when backed by unresolved evidence.",
            citations=["evidence:unresolved-source-ref"],
            metadata={"source_refs": ["evidence:unresolved-source-ref"]},
        )

        packet = ContextAssembler().assemble(
            [invalid_evidence, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OBSERVED_EVIDENCE"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:unresolved-source-ref"], "invalid_citation")
        self.assertEqual(omitted_refs["model:unresolved-evidence-backed-summary"], "invalid_citation")
        self.assertNotIn("backed by unresolved evidence", packet["rendered"])

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

        packet = ContextAssembler().assemble(
            envelopes,
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

    def test_context_assembler_policy_gate_rejects_advisory_candidate_task_sources(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="task:normalized-candidate",
                kind="candidate_task",
                authority="asserted",
                source_type="runtime_state",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A normalized candidate action may be evaluated by the policy gate.",
                citations=[],
            ),
            ContextEnvelope(
                ref="task:writeup-candidate",
                kind="candidate_task",
                authority="advisory",
                source_type="writeup",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A writeup-derived action must not enter the policy gate prompt.",
                citations=["rag:writeup-step"],
            ),
            ContextEnvelope(
                ref="task:vuln-intel-candidate",
                kind="candidate_task",
                authority="advisory",
                source_type="vuln_intel",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A vulnerability-intel hint must not enter the policy gate prompt as a task.",
                citations=["rag:cve-hint"],
            ),
            ContextEnvelope(
                ref="task:github-candidate",
                kind="candidate_task",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A GitHub issue must not enter the policy gate prompt as a task.",
                citations=["github:issue-1"],
            ),
            ContextEnvelope(
                ref="task:ctfd-candidate",
                kind="candidate_task",
                authority="asserted",
                source_type="ctfd",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="CTFd challenge text must not enter the policy gate prompt as a task.",
                citations=["ctfd:challenge-1"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="policy_gate",
            role="policy_gate",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(
            [item["ref"] for item in packet["sections"]["MODEL_DERIVED"]],
            ["task:normalized-candidate"],
        )
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["task:writeup-candidate"], "role_forbidden")
        self.assertEqual(omitted_refs["task:vuln-intel-candidate"], "role_forbidden")
        self.assertEqual(omitted_refs["task:github-candidate"], "role_forbidden")
        self.assertEqual(omitted_refs["task:ctfd-candidate"], "role_forbidden")
        self.assertNotIn("writeup-derived action", packet["rendered"])
        self.assertNotIn("vulnerability-intel hint", packet["rendered"])
        self.assertNotIn("GitHub issue", packet["rendered"])
        self.assertNotIn("CTFd challenge", packet["rendered"])

    def test_context_assembler_policy_gate_rejects_truth_like_model_candidate_tasks(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="task:model-derived-candidate",
                kind="candidate_task",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A model-derived candidate action may be evaluated by the policy gate.",
                citations=[],
            ),
            ContextEnvelope(
                ref="task:model-observed-candidate",
                kind="candidate_task",
                authority="observed",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A model-derived candidate action must not claim observed authority.",
                citations=[],
            ),
            ContextEnvelope(
                ref="task:model-confirmed-candidate",
                kind="candidate_task",
                authority="confirmed",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A model-derived candidate action must not claim confirmed authority.",
                citations=[],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="policy_gate",
            role="policy_gate",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(
            [item["ref"] for item in packet["sections"]["MODEL_DERIVED"]],
            ["task:model-derived-candidate"],
        )
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["task:model-observed-candidate"], "role_forbidden")
        self.assertEqual(omitted_refs["task:model-confirmed-candidate"], "role_forbidden")
        self.assertNotIn("claim observed authority", packet["rendered"])
        self.assertNotIn("claim confirmed authority", packet["rendered"])

    def test_context_assembler_omits_truth_like_github_and_notion_prompt_refs(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="github:reviewed-issue",
                kind="github_ref",
                authority="reviewed",
                source_type="github",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="methodology_hint",
                sink="prompt",
                content="GitHub issue text must not enter prompt as reviewed target truth.",
                citations=["github:reviewed-issue"],
            ),
            ContextEnvelope(
                ref="notion:confirmed-note",
                kind="notion_ref",
                authority="confirmed",
                source_type="notion",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="methodology_hint",
                sink="prompt",
                content="Notion note text must not enter prompt as confirmed target truth.",
                citations=["notion:confirmed-note"],
            ),
            ContextEnvelope(
                ref="github:engineering-note",
                kind="github_ref",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="methodology_hint",
                sink="prompt",
                content="GitHub issue can remain labeled as engineering collaboration context.",
                citations=["github:engineering-note"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="methodology_hint",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        collaboration_refs = [item["ref"] for item in packet["sections"]["COLLABORATION_REFS"]]
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}

        self.assertEqual(collaboration_refs, ["github:engineering-note"])
        self.assertEqual(omitted_refs["github:reviewed-issue"], "collaboration_truth_like_authority")
        self.assertEqual(omitted_refs["notion:confirmed-note"], "collaboration_truth_like_authority")
        self.assertNotIn("reviewed target truth", packet["rendered"])
        self.assertNotIn("confirmed target truth", packet["rendered"])
        self.assertIn("engineering collaboration context", packet["rendered"])

    def test_context_assembler_omits_truth_like_ctfd_prompt_refs_from_import_lanes(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="ctfd:reviewed-imported-ref",
                kind="ctfd_ref",
                authority="reviewed",
                source_type="ctf_manifest",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="methodology_hint",
                sink="prompt",
                content="CTFd imported reference must not enter prompt as reviewed target truth.",
                citations=["ctfd:reviewed-imported-ref"],
            ),
            ContextEnvelope(
                ref="ctfd:asserted-imported-ref",
                kind="ctfd_ref",
                authority="asserted",
                source_type="ctf_manifest",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="methodology_hint",
                sink="prompt",
                content="CTFd imported reference can remain labeled as collaboration context.",
                citations=["ctfd:asserted-imported-ref"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="methodology_hint",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        collaboration_refs = [item["ref"] for item in packet["sections"]["COLLABORATION_REFS"]]
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}

        self.assertEqual(collaboration_refs, ["ctfd:asserted-imported-ref"])
        self.assertEqual(omitted_refs["ctfd:reviewed-imported-ref"], "ctfd_truth_like_authority")
        self.assertNotIn("reviewed target truth", packet["rendered"])
        self.assertIn("collaboration context", packet["rendered"])

    def test_context_assembler_keeps_asserted_ctfd_submission_results_in_collaboration_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:submission-result",
            kind="submission_result",
            authority="asserted",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="methodology_hint",
            sink="prompt",
            content="CTFd submission result is collaboration context, not model-derived context.",
            citations=["ctfd:submission-result"],
        )

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="methodology_hint",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["COLLABORATION_REFS"]], ["ctfd:submission-result"])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        self.assertIn("CTFd submission result", packet["rendered"])

    def test_context_assembler_evidence_reviewer_omits_advisory_and_model_context(self) -> None:
        def envelope(ref: str, kind: str, authority: str, source_type: str, content: str) -> ContextEnvelope:
            return ContextEnvelope(
                ref=ref,
                kind=kind,
                authority=authority,
                source_type=source_type,
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="evidence_review",
                sink="prompt",
                content=content,
                citations=[] if ref.startswith("model:") else [ref],
            )

        envelopes = [
            envelope("policy_decision:current", "policy_decision", "authoritative", "runtime_state", "Current intent is recon_only."),
            envelope("evidence:banner", "evidence", "observed", "tool_output", "HTTP response header reports nginx."),
            envelope("note:operator-1", "operator_note", "asserted", "manual_artifact", "Operator suspects the banner may be behind a proxy."),
            envelope("rag:writeup-1", "rag", "advisory", "writeup", "A writeup claims the target has an admin bypass."),
            envelope("rag:cve-1", "rag", "advisory", "vuln_intel", "Exploit advisory text describes nginx preconditions."),
            envelope("model:summary-1", "model_summary", "derived", "ai_output", "The model concludes the admin bypass is proven."),
            envelope("github:issue-1", "github_ref", "asserted", "github", "An issue says the scanner should report the bypass."),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="evidence_review",
            role="evidence_reviewer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        authority_refs = [item["ref"] for item in packet["sections"]["AUTHORITATIVE_RUNTIME_STATE"]]
        evidence_refs = [item["ref"] for item in packet["sections"]["OBSERVED_EVIDENCE"]]
        note_refs = [item["ref"] for item in packet["sections"]["OPERATOR_NOTES"]]
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}

        self.assertIn("policy_decision:current", authority_refs)
        self.assertEqual(evidence_refs, ["evidence:banner"])
        self.assertEqual(note_refs, ["note:operator-1"])
        for ref in ("rag:writeup-1", "rag:cve-1", "model:summary-1", "github:issue-1"):
            self.assertEqual(omitted_refs[ref], "role_forbidden")
        for section_name in ("RAG_ADVISORY", "MODEL_DERIVED", "COLLABORATION_REFS"):
            self.assertEqual(packet["sections"][section_name], [])
        rendered = packet["rendered"]
        self.assertIn("HTTP response header reports nginx.", rendered)
        self.assertIn("Operator suspects the banner", rendered)
        for omitted_text in ("writeup claims", "Exploit advisory", "issue says"):
            self.assertNotIn(omitted_text, rendered)
        self.assertNotIn("model concludes", rendered.lower())

    def test_context_assembler_ctf_solver_omits_closed_book_mode_alias_writeup(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "closed-book-mode-alias-writeup",
                "citation_id": "rag:closed-book-mode-alias-writeup",
                "source_type": "writeup",
                "text": "A closed-book mode alias writeup reveals the exact solve path.",
                "metadata": {"benchmark_mode": "closed_book_mode"},
            },
            purpose="ctf_solver_context",
            sink="prompt",
            target_id="lab-target",
            active_generation_id="generation:2",
        )

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="ctf_solver_context",
            role="ctf_solver_orchestrator",
            target_id="lab-target",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:closed-book-mode-alias-writeup"], "closed_book_forbidden")
        self.assertNotIn("exact solve path", packet["rendered"])

    def test_context_assembler_ctf_solver_omits_nested_writeups_disabled_writeup(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "nested-writeups-disabled",
                "citation_id": "rag:nested-writeups-disabled",
                "source_type": "writeup",
                "text": "Nested writeup deny metadata must not enter closed-book prompts.",
                "metadata": {"metadata": {"writeups_allowed": False}},
            },
            purpose="ctf_solver_context",
            sink="prompt",
            target_id="lab-target",
            active_generation_id="generation:2",
        )

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="ctf_solver_context",
            role="ctf_solver_orchestrator",
            target_id="lab-target",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:nested-writeups-disabled"], "writeups_forbidden")
        self.assertNotIn("Nested writeup deny metadata", packet["rendered"])

    def test_context_assembler_omits_rag_chunk_from_generated_export_path(self) -> None:
        envelopes = [
            ContextEnvelope.from_rag_chunk(
                {
                    "chunk_id": "methodology",
                    "citation_id": "rag:methodology",
                    "text": "Methodology advisory material may enter operational prompts.",
                    "metadata": {
                        "source_type": "methodology_doc",
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                },
                purpose="planner",
                sink="prompt",
                target_id="target-a",
                active_generation_id="generation:2",
            ),
            ContextEnvelope.from_rag_chunk(
                {
                    "chunk_id": "legacy-generated-export-path",
                    "citation_id": "rag:legacy-generated-export-path",
                    "text": "Generated export prose must not enter operational prompts.",
                    "metadata": {
                        "source_type": "methodology_doc",
                        "source_file": "findings/notion/rag.htb/notion-export.md",
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                },
                purpose="planner",
                sink="prompt",
                target_id="target-a",
                active_generation_id="generation:2",
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:methodology"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:legacy-generated-export-path"], "generated_export")
        self.assertNotIn("Generated export prose", packet["rendered"])

    def test_context_assembler_omits_rag_chunk_from_human_readable_generated_export_path(self) -> None:
        envelopes = [
            ContextEnvelope.from_rag_chunk(
                {
                    "chunk_id": "methodology",
                    "citation_id": "rag:methodology",
                    "text": "Methodology advisory material may enter operational prompts.",
                    "metadata": {
                        "source_type": "methodology_doc",
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                },
                purpose="planner",
                sink="prompt",
                target_id="target-a",
                active_generation_id="generation:2",
            ),
            ContextEnvelope.from_rag_chunk(
                {
                    "chunk_id": "display-generated-export-path",
                    "citation_id": "rag:display-generated-export-path",
                    "text": "Generated export prose with display metadata must not enter operational prompts.",
                    "metadata": {
                        "source_type": "methodology_doc",
                        "Source file": "findings/notion/rag.htb/notion-export.md",
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                },
                purpose="planner",
                sink="prompt",
                target_id="target-a",
                active_generation_id="generation:2",
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:methodology"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:display-generated-export-path"], "generated_export")
        self.assertNotIn("Generated export prose", packet["rendered"])

    def test_context_assembler_omits_rag_chunk_from_generated_export_source_url(self) -> None:
        envelopes = [
            ContextEnvelope.from_rag_chunk(
                {
                    "chunk_id": "methodology",
                    "citation_id": "rag:methodology",
                    "text": "Methodology advisory material may enter operational prompts.",
                    "metadata": {
                        "source_type": "methodology_doc",
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                },
                purpose="planner",
                sink="prompt",
                target_id="target-a",
                active_generation_id="generation:2",
            ),
            ContextEnvelope.from_rag_chunk(
                {
                    "chunk_id": "generated-export-source-url",
                    "citation_id": "rag:generated-export-source-url",
                    "text": "Generated export prose from URL metadata must not enter operational prompts.",
                    "metadata": {
                        "source_type": "methodology_doc",
                        "source_url": "https://example.invalid/findings/notion/rag.htb/notion-export.md",
                        "corpus_type": "methodology_standards",
                        "domain": "methodology_standards",
                    },
                },
                purpose="planner",
                sink="prompt",
                target_id="target-a",
                active_generation_id="generation:2",
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:methodology"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:generated-export-source-url"], "generated_export")
        self.assertNotIn("Generated export prose", packet["rendered"])

    def test_context_assembler_omits_nested_operational_retrieval_disabled_rag(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "nested-retrieval-disabled",
                "citation_id": "rag:nested-retrieval-disabled",
                "text": "Nested retrieval deny metadata must not enter operational prompts.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "metadata": {"operational_retrieval_allowed": False},
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            },
            purpose="planner",
            sink="prompt",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:nested-retrieval-disabled"], "operational_retrieval_disabled")
        self.assertNotIn("Nested retrieval deny metadata", packet["rendered"])

    def test_context_assembler_omits_list_valued_operational_retrieval_disabled_rag(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "list-retrieval-disabled",
                "citation_id": "rag:list-retrieval-disabled",
                "text": "List-valued retrieval deny metadata must not enter operational prompts.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "metadata": {"operational_retrieval_allowed": [True, False]},
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            },
            purpose="planner",
            sink="prompt",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:list-retrieval-disabled"], "operational_retrieval_disabled")
        self.assertNotIn("List-valued retrieval deny metadata", packet["rendered"])

    def test_context_assembler_omits_model_refs_against_nested_retrieval_disabled_rag(self) -> None:
        disabled_rag = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "nested-disabled-model-source",
                "citation_id": "rag:nested-disabled-model-source",
                "text": "Nested retrieval deny metadata must not satisfy model provenance.",
                "metadata": {
                    "source_type": "methodology_doc",
                    "metadata": {"operational_retrieval_allowed": False},
                    "corpus_type": "methodology_standards",
                    "domain": "methodology_standards",
                },
            },
            purpose="planner",
            sink="prompt",
            target_id="target-a",
            active_generation_id="generation:2",
        )
        model_summary = ContextEnvelope(
            ref="model:nested-disabled-rag-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="planner",
            sink="prompt",
            content="Model output must not resolve against retrieval-disabled RAG.",
            citations=["rag:nested-disabled-model-source"],
            metadata={"source_refs": ["rag:nested-disabled-model-source"]},
        )

        packet = ContextAssembler().assemble(
            [disabled_rag, model_summary],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:nested-disabled-model-source"], "operational_retrieval_disabled")
        self.assertEqual(omitted_refs["model:nested-disabled-rag-backed"], "invalid_citation")
        self.assertNotIn("retrieval-disabled RAG", packet["rendered"])

    def test_context_assembler_report_writer_omits_uncited_ai_and_raw_chat(self) -> None:
        def envelope(ref: str, kind: str, authority: str, source_type: str, citations: list[str]) -> ContextEnvelope:
            return ContextEnvelope(
                ref=ref,
                kind=kind,
                authority=authority,
                source_type=source_type,
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="report_generation",
                sink="prompt",
                content=f"{ref} report context.",
                citations=citations,
            )

        envelopes = [
            envelope("evidence:banner", "evidence", "observed", "tool_output", ["evidence:banner"]),
            envelope("finding:web-1", "finding", "reviewed", "runtime_state", ["evidence:banner"]),
            envelope("note:operator-1", "operator_note", "asserted", "manual_artifact", ["note:operator-1"]),
            envelope("rag:method-1", "rag", "advisory", "methodology_doc", ["rag:method-1"]),
            envelope("model:summary-cited", "model_summary", "derived", "ai_output", ["evidence:banner"]),
            envelope("model:summary-uncited", "model_summary", "derived", "ai_output", []),
            envelope("chat:raw-1", "operator_note", "asserted", "chat", ["chat:raw-1"]),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["OBSERVED_EVIDENCE"]], ["evidence:banner"])
        self.assertEqual([item["ref"] for item in packet["sections"]["REVIEWED_FINDINGS"]], ["finding:web-1"])
        self.assertEqual([item["ref"] for item in packet["sections"]["OPERATOR_NOTES"]], ["note:operator-1"])
        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:method-1"])
        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:summary-cited"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["model:summary-uncited"], "missing_citation")
        self.assertEqual(omitted_refs["chat:raw-1"], "raw_chat_context")
        self.assertNotIn("model:summary-uncited report context", packet["rendered"])
        self.assertNotIn("chat:raw-1 report context", packet["rendered"])

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

    def test_context_assembler_omits_model_context_with_placeholder_source_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:placeholder-note-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content="Placeholder source citations must not render as model context.",
            citations=["note:null"],
        )

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["model:placeholder-note-summary"], "invalid_citation")
        self.assertNotIn("Placeholder source citations", packet["rendered"])

    def test_context_assembler_rejects_ai_output_disguised_as_operator_note(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="note:model-generated",
                kind="operator_note",
                authority="asserted",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="AI output must not enter the operator note lane.",
                citations=["note:model-generated"],
            ),
            ContextEnvelope(
                ref="model:note-backed",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Derived context must not cite a model-generated note.",
                citations=["note:model-generated"],
                metadata={"source_refs": ["note:model-generated"]},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OPERATOR_NOTES"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["note:model-generated"], "non_operator_note_source")
        self.assertEqual(omitted_refs["model:note-backed"], "invalid_citation")
        self.assertNotIn("AI output must not enter", packet["rendered"])

    def test_context_assembler_rejects_model_target_fact_backed_by_sensitive_evidence(self) -> None:
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
                content="Sensitive evidence must not enter prompt context.",
                citations=["evidence:secret"],
                metadata={"contains_secret": True},
            ),
            ContextEnvelope(
                ref="model:secret-backed-target-fact",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Derived target fact must not cite omitted sensitive evidence.",
                citations=["evidence:secret"],
                metadata={"contains_target_fact": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["OBSERVED_EVIDENCE"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["evidence:secret"], "sensitive_material")
        self.assertEqual(omitted_refs["model:secret-backed-target-fact"], "invalid_citation")
        self.assertNotIn("Sensitive evidence must not enter", packet["rendered"])
        self.assertNotIn("Derived target fact must not cite", packet["rendered"])

    def test_context_assembler_rejects_model_advisory_backed_by_target_fact_rag(self) -> None:
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
                content="RAG target fact material must not enter prompt context.",
                citations=["rag:target-fact"],
                metadata={"contains_target_fact": True},
            ),
            ContextEnvelope(
                ref="model:target-fact-rag-advisory",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="planner",
                sink="prompt",
                content="Derived advisory must not cite omitted target-fact RAG.",
                citations=["rag:target-fact"],
                metadata={"advisory_claim": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:target-fact"], "target_fact_rag")
        self.assertEqual(omitted_refs["model:target-fact-rag-advisory"], "invalid_citation")
        self.assertNotIn("RAG target fact material", packet["rendered"])
        self.assertNotIn("Derived advisory must not cite", packet["rendered"])


if __name__ == "__main__":
    unittest.main()
