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


if __name__ == "__main__":
    unittest.main()
