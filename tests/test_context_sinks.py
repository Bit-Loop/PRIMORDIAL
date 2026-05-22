from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextSinkValidatorTests(unittest.TestCase):
    def test_evidence_sink_rejects_evidence_shaped_non_proof_sources(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:ctfd-challenge-text",
                kind="evidence",
                authority="observed",
                source_type="ctfd",
                purpose="evidence_review",
                sink="evidence",
                content="CTFd challenge text says the target has a web login.",
                citations=["evidence:ctfd-challenge-text"],
            ),
            ContextEnvelope(
                ref="evidence:github-issue",
                kind="evidence",
                authority="observed",
                source_type="github",
                purpose="evidence_review",
                sink="evidence",
                content="A GitHub issue claims the scanner proved exploitability.",
                citations=["evidence:github-issue"],
            ),
            ContextEnvelope(
                ref="evidence:generated-export",
                kind="evidence",
                authority="observed",
                source_type="generated_export",
                purpose="evidence_review",
                sink="evidence",
                content="Generated Notion export prose repeats an AI strategy summary.",
                citations=["evidence:generated-export"],
            ),
        ]

        result = ContextSinkValidator().validate("evidence", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(
            result.rejected_refs,
            ["evidence:ctfd-challenge-text", "evidence:generated-export", "evidence:github-issue"],
        )
        self.assertEqual(result.accepted_refs, [])
        for source_type in ("ctfd", "github", "generated_export"):
            self.assertTrue(any(f"source_type={source_type}" in error for error in result.errors))

    def test_evidence_sink_rejects_rag_cited_evidence_records(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:rag-backed-service",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            purpose="evidence_review",
            sink="evidence",
            content="A RAG-only service claim must not become observed evidence.",
            citations=["rag:service-claim"],
        )

        result = ContextSinkValidator().validate("evidence", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:rag-backed-service"])
        self.assertTrue(any("rag citation" in error for error in result.errors))

    def test_evidence_sink_rejects_non_evidence_citation_support(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:model-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="Model summary support must not become observed evidence.",
                citations=["model:summary"],
            ),
            ContextEnvelope(
                ref="evidence:github-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="GitHub issue support must not become observed evidence.",
                citations=["github:issue-1"],
            ),
            ContextEnvelope(
                ref="evidence:notion-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="Notion note support must not become observed evidence.",
                citations=["notion:note-1"],
            ),
            ContextEnvelope(
                ref="evidence:ctfd-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="CTFd challenge prose support must not become observed evidence.",
                citations=["ctfd:challenge-1"],
            ),
            ContextEnvelope(
                ref="evidence:chat-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="Chat support must not become observed evidence.",
                citations=["chat:operator-context"],
            ),
            ContextEnvelope(
                ref="evidence:self-backed",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                purpose="evidence_review",
                sink="evidence",
                content="Evidence-supported evidence remains acceptable.",
                citations=["evidence:self-backed"],
            ),
        ]

        result = ContextSinkValidator().validate("evidence", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:self-backed"])
        self.assertEqual(
            result.rejected_refs,
            [
                "evidence:chat-backed",
                "evidence:ctfd-backed",
                "evidence:github-backed",
                "evidence:model-backed",
                "evidence:notion-backed",
            ],
        )
        self.assertTrue(any("non-evidence citation support" in error for error in result.errors))

    def test_task_metadata_sink_rejects_profile_label_as_executable_permission(self) -> None:
        envelope = ContextEnvelope(
            ref="task:credential-validation",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Validate captured credentials because the profile is hack_the_box.",
            citations=["policy_decision:profile-label", "evidence:credential-artifact"],
            metadata={
                "active_intent": "recon_only",
                "engagement_profile": "hack_the_box",
                "action_class": "credential_validation",
                "creates_executable_task": True,
                "permission_source": "profile_label",
                "supporting_evidence_refs": ["evidence:credential-artifact"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["task:credential-validation"])
        self.assertTrue(any("profile label" in error for error in result.errors))

    def test_task_metadata_sink_rejects_writeup_derived_executable_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="task:writeup-exploit-step",
            kind="candidate_task",
            authority="asserted",
            source_type="writeup",
            target_id="target-a",
            purpose="task_generation",
            sink="task_metadata",
            content="Run the exploit step because the writeup says it is the path forward.",
            citations=["policy_decision:assisted-lab", "evidence:observed-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "exploit_validation",
                "creates_executable_task": True,
                "permission_basis": "writeup",
                "supporting_evidence_refs": ["evidence:observed-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["task:writeup-exploit-step"])
        self.assertTrue(any("writeup-derived action authority" in error for error in result.errors))

    def test_task_metadata_sink_rejects_stale_generation_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:old-generation-service-check",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:1",
            purpose="task_generation",
            sink="task_metadata",
            content="Probe a service observed only during an old active-IP generation.",
            citations=["policy_decision:assisted-lab", "evidence:old-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:old-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["task:old-generation-service-check"])
        self.assertTrue(any("stale generation" in error for error in result.errors))

    def test_task_metadata_sink_rejects_wrong_target_executable_task(self) -> None:
        envelope = ContextEnvelope(
            ref="task:wrong-target-service-check",
            kind="candidate_task",
            authority="asserted",
            source_type="tool_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="task_generation",
            sink="task_metadata",
            content="Probe a service observed for a different current target.",
            citations=["policy_decision:assisted-lab", "evidence:target-a-service"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "action_class": "tool_execution",
                "creates_executable_task": True,
                "current_target_id": "target-b",
                "current_active_generation_id": "generation:2",
                "supporting_evidence_refs": ["evidence:target-a-service"],
            },
        )

        result = ContextSinkValidator().validate("task_metadata", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.rejected_refs, ["task:wrong-target-service-check"])
        self.assertTrue(any("wrong target" in error for error in result.errors))

    def test_notion_export_quarantines_uncited_rag_advisory(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:uncited-methodology",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Advisory RAG material must preserve its rag citation in exports.",
            citations=[],
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.quarantined_refs, ["rag:uncited-methodology"])
        self.assertTrue(any("missing rag citation" in error for error in result.errors))

    def test_rag_index_rejects_closed_book_writeups_and_hidden_solution_material(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:cve-advisory",
                kind="rag",
                authority="advisory",
                source_type="vuln_intel",
                purpose="vuln_hint",
                sink="rag_index",
                content="Advisory CVE context may be indexed as advisory material.",
                citations=["rag:cve-advisory"],
            ),
            ContextEnvelope(
                ref="rag:hidden-solution",
                kind="rag",
                authority="advisory",
                source_type="ctf_manifest",
                purpose="ctf_benchmark",
                sink="rag_index",
                content="Hidden solution material must not enter the active RAG index.",
                citations=["rag:hidden-solution"],
                metadata={"benchmark_mode": "closed_book", "hidden_solution_material": True},
            ),
            ContextEnvelope(
                ref="rag:closed-book-writeup",
                kind="rag",
                authority="advisory",
                source_type="writeup",
                purpose="ctf_benchmark",
                sink="rag_index",
                content="Target-specific writeups are disallowed in closed-book mode.",
                citations=["rag:closed-book-writeup"],
                metadata={"benchmark_mode": "closed_book", "writeup_access_policy": "forbidden"},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:cve-advisory"])
        self.assertEqual(result.rejected_refs, ["rag:closed-book-writeup", "rag:hidden-solution"])
        self.assertTrue(any("hidden solution material" in error for error in result.errors))
        self.assertTrue(any("writeup" in error and "closed_book" in error for error in result.errors))

    def test_rag_index_normalizes_human_readable_closed_book_mode(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:display-closed-book-writeup",
            kind="rag",
            authority="advisory",
            source_type="writeup",
            purpose="ctf_benchmark",
            sink="rag_index",
            content="Display-mode closed-book writeups must not enter the active RAG index.",
            citations=["rag:display-closed-book-writeup"],
            metadata={"benchmark_mode": "Closed book"},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:display-closed-book-writeup"])
        self.assertTrue(any("writeup" in error and "closed_book" in error for error in result.errors))

    def test_rag_index_rejects_string_encoded_generated_export_deny_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="model:string-denied-export-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="cleanup",
            sink="rag_index",
            content="String-encoded deny metadata must not let generated exports enter active RAG.",
            citations=["evidence:current"],
            metadata={
                "Origin": "generated export",
                "Ingest allowed": "false",
                "Operational retrieval allowed": "no",
            },
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:string-denied-export-summary"])
        self.assertTrue(any("ingest_allowed=false" in error for error in result.errors))

    def test_rag_index_rejects_generated_export_origin_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="model:export-origin-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="cleanup",
            sink="rag_index",
            content="Generated export origin metadata must keep summaries out of active RAG.",
            citations=["evidence:current"],
            metadata={"Origin": "generated export"},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:export-origin-summary"])
        self.assertTrue(any("generated export" in error for error in result.errors))

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

    def test_report_sink_rejects_uncited_ai_target_facts_and_raw_flags(self) -> None:
        accepted = ContextEnvelope(
            ref="finding:web-1",
            kind="finding",
            authority="reviewed",
            source_type="runtime_state",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="Reviewed finding supported by evidence.",
            citations=["evidence:banner"],
        )
        envelopes = [
            accepted,
            ContextEnvelope(
                ref="model:uncited-summary",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Uncited AI summary should not enter reports.",
                citations=[],
            ),
            ContextEnvelope(
                ref="model:target-fact",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Target fact backed only by advisory RAG.",
                citations=["rag:method-1"],
                metadata={"contains_target_fact": True},
            ),
            ContextEnvelope(
                ref="ctfd:raw-flag",
                kind="ctfd_ref",
                authority="asserted",
                source_type="ctfd",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Raw hidden flag material must not be reported.",
                citations=[],
                metadata={"contains_raw_flag": True},
            ),
        ]

        result = ContextSinkValidator().validate("report", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["finding:web-1"])
        self.assertEqual(
            result.rejected_refs,
            ["ctfd:raw-flag", "model:target-fact", "model:uncited-summary"],
        )
        self.assertTrue(any("requires citations for AI-derived" in error for error in result.errors))
        self.assertTrue(any("requires evidence:<id>" in error for error in result.errors))
        self.assertTrue(any("hidden or raw sensitive material" in error for error in result.errors))

if __name__ == "__main__":
    unittest.main()
