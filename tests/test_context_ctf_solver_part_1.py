from __future__ import annotations

from tests.test_context_ctf_solver_common import *


class CtfSolverContextTestsPart1(CtfSolverContextTestsBase):
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

    def test_ctf_solver_treats_writeup_corpus_rag_payload_as_writeup(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "closed-book-writeup-corpus",
                "citation_id": "rag:closed-book-writeup-corpus",
                "text": "A closed-book writeup corpus chunk reveals a target-specific path.",
                "metadata": {"benchmark_mode": "closed_book", "corpus_type": "htb_writeup"},
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

        self.assertEqual(envelope.source_type, "writeup")
        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:closed-book-writeup-corpus"], "closed_book_forbidden")
        self.assertNotIn("target-specific path", packet["rendered"])

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

    def test_ctf_solver_rejects_model_advisory_claims_backed_by_active_postmortem_only_writeups(self) -> None:
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
                ref="rag:postmortem-only-writeup",
                kind="rag",
                authority="advisory",
                source_type="writeup",
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content="Active solve prompts must not use postmortem-only writeup material.",
                citations=["rag:postmortem-only-writeup"],
                metadata={"writeup_access_policy": "postmortem_only"},
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
                ref="model:postmortem-only-backed",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content="Derived advisory summary based on postmortem-only writeup material.",
                citations=["rag:postmortem-only-writeup"],
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
        self.assertEqual(omitted_refs["rag:postmortem-only-writeup"], "postmortem_only_forbidden")
        self.assertEqual(omitted_refs["model:postmortem-only-backed"], "invalid_citation")
        self.assertNotIn("model:postmortem-only-backed", packet["rendered"])

__all__ = ["CtfSolverContextTestsPart1"]
