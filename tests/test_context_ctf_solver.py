from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope


class CtfSolverContextTests(unittest.TestCase):
    def test_ctf_solver_omits_closed_book_writeup_wrapped_from_rag_payload(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "closed-book-writeup-payload",
                "citation_id": "rag:closed-book-writeup-payload",
                "source_type": "writeup",
                "text": "A closed-book writeup reveals the exact solve path.",
                "metadata": {"benchmark_mode": "closed_book"},
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
        self.assertEqual(omitted_refs["rag:closed-book-writeup-payload"], "closed_book_forbidden")
        self.assertNotIn("exact solve path", packet["rendered"])

    def test_ctf_solver_normalizes_human_readable_closed_book_mode(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "display-closed-book-writeup",
                "citation_id": "rag:display-closed-book-writeup",
                "source_type": "writeup",
                "text": "A display-mode writeup reveals the exact solve path.",
                "metadata": {"benchmark_mode": "Closed book"},
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
        self.assertEqual(omitted_refs["rag:display-closed-book-writeup"], "closed_book_forbidden")
        self.assertNotIn("exact solve path", packet["rendered"])

    def test_ctf_solver_normalizes_human_readable_closed_book_metadata_key(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "display-key-closed-book-writeup",
                "citation_id": "rag:display-key-closed-book-writeup",
                "source_type": "writeup",
                "text": "A display-key writeup reveals the exact solve path.",
                "metadata": {"Benchmark mode": "Closed book"},
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
        self.assertEqual(omitted_refs["rag:display-key-closed-book-writeup"], "closed_book_forbidden")
        self.assertNotIn("exact solve path", packet["rendered"])

    def test_ctf_solver_rejects_model_advisory_claims_backed_by_closed_book_writeups(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:generic-method",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content="Generic methodology is allowed in solver context.",
                citations=["rag:generic-method"],
            ),
            ContextEnvelope(
                ref="rag:closed-book-writeup",
                kind="rag",
                authority="advisory",
                source_type="writeup",
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content="Closed-book writeup reveals the exact solve path.",
                citations=["rag:closed-book-writeup"],
                metadata={"benchmark_mode": "closed_book"},
            ),
            ContextEnvelope(
                ref="model:generic-method",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content="Derived advisory summary based on generic methodology.",
                citations=["rag:generic-method"],
                metadata={"advisory_claim": True},
            ),
            ContextEnvelope(
                ref="model:writeup-backed",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content="Derived advisory summary based on closed-book writeup material.",
                citations=["rag:closed-book-writeup"],
                metadata={"advisory_claim": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="ctf_solver_context",
            role="ctf_solver_orchestrator",
            target_id="lab-target",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:generic-method"])
        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:generic-method"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:closed-book-writeup"], "closed_book_forbidden")
        self.assertEqual(omitted_refs["model:writeup-backed"], "invalid_citation")
        self.assertNotIn("model:writeup-backed", packet["rendered"])

    def test_ctf_solver_context_omits_closed_book_solution_material(self) -> None:
        def envelope(
            ref: str,
            kind: str,
            source_type: str,
            content: str,
            metadata: dict[str, object] | None = None,
        ) -> ContextEnvelope:
            return ContextEnvelope(
                ref=ref,
                kind=kind,
                authority="advisory" if kind == "rag" else "asserted",
                source_type=source_type,
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content=content,
                citations=[ref],
                metadata=metadata or {},
            )

        envelopes = [
            envelope("evidence:http-title", "evidence", "tool_output", "HTTP title observed from the lab target."),
            envelope("rag:methodology", "rag", "methodology_doc", "Generic web enumeration methodology."),
            envelope("ctfd:challenge-1", "ctfd_ref", "ctfd", "Challenge title and category, no hidden flag."),
            envelope(
                "rag:closed-book-writeup",
                "rag",
                "writeup",
                "A writeup reveals the exact solve path.",
                {"benchmark_mode": "closed_book"},
            ),
            envelope(
                "model:prior-trace",
                "model_summary",
                "ai_output",
                "Prior generated solve trace for this same target.",
                {"prior_solve_trace": True, "benchmark_mode": "closed_book"},
            ),
            envelope(
                "ctfd:expected-flag",
                "ctfd_ref",
                "ctfd",
                "The hidden expected flag value.",
                {"contains_raw_expected_flag": True},
            ),
            envelope(
                "ctf:hidden-solution",
                "rag",
                "ctf_manifest",
                "Hidden benchmark solution material.",
                {"hidden_solution_material": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="ctf_solver_context",
            role="ctf_solver_orchestrator",
            target_id="lab-target",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["OBSERVED_EVIDENCE"]], ["evidence:http-title"])
        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:methodology"])
        self.assertEqual([item["ref"] for item in packet["sections"]["COLLABORATION_REFS"]], ["ctfd:challenge-1"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:closed-book-writeup"], "closed_book_forbidden")
        self.assertEqual(omitted_refs["model:prior-trace"], "closed_book_forbidden")
        self.assertEqual(omitted_refs["ctfd:expected-flag"], "sensitive_material")
        self.assertEqual(omitted_refs["ctf:hidden-solution"], "sensitive_material")
        self.assertNotIn("exact solve path", packet["rendered"])
        self.assertNotIn("Prior generated solve trace", packet["rendered"])
        self.assertNotIn("hidden expected flag", packet["rendered"])

    def test_ctf_solver_labels_ctfd_registry_records_as_collaboration_refs(self) -> None:
        def ctfd_record(ref: str, kind: str, record_type: str, content: str) -> ContextEnvelope:
            return ContextEnvelope(
                ref=ref,
                kind=kind,
                authority="asserted",
                source_type="ctfd",
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content=content,
                citations=["ctfd:challenge-1"],
                metadata={"record_type": record_type, "challenge_id": "1"},
            )

        envelopes = [
            ctfd_record(
                "ctfd:challenge-1",
                "challenge_metadata",
                "challenge_metadata",
                "Challenge title and category, no hidden flag.",
            ),
            ctfd_record(
                "ctfd:scoreboard-1",
                "scoreboard_projection",
                "scoreboard_projection",
                "Scoreboard projection says the challenge is unsolved.",
            ),
            ctfd_record(
                "ctfd:solve-status-1",
                "solve_status",
                "solve_status",
                "Solve status projection says no flag has been submitted.",
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="ctf_solver_context",
            role="ctf_solver_orchestrator",
            target_id="lab-target",
            active_generation_id="generation:2",
        )

        self.assertEqual(
            [item["ref"] for item in packet["sections"]["COLLABORATION_REFS"]],
            ["ctfd:challenge-1", "ctfd:scoreboard-1", "ctfd:solve-status-1"],
        )
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        self.assertIn("COLLABORATION_REFS:", packet["rendered"])
        self.assertNotIn("MODEL_DERIVED:", packet["rendered"])

    def test_ctf_solver_omits_ctfd_records_with_truth_like_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:confirmed-challenge",
            kind="challenge_metadata",
            authority="confirmed",
            source_type="ctfd",
            target_id="lab-target",
            active_generation_id="generation:2",
            purpose="ctf_solver_context",
            sink="prompt",
            content="CTFd challenge metadata must not enter solver context as confirmed target truth.",
            citations=["ctfd:confirmed-challenge"],
            metadata={"record_type": "challenge_metadata", "challenge_id": "confirmed-challenge"},
        )

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="ctf_solver_context",
            role="ctf_solver_orchestrator",
            target_id="lab-target",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["COLLABORATION_REFS"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["ctfd:confirmed-challenge"], "ctfd_truth_like_authority")
        self.assertNotIn("confirmed target truth", packet["rendered"])


if __name__ == "__main__":
    unittest.main()
