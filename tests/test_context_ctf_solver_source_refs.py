from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope


class CtfSolverSourceRefsTests(unittest.TestCase):
    def test_ctf_solver_rejects_model_summary_with_hidden_closed_book_source_refs(self) -> None:
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
                ref="model:hidden-writeup-backed",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content="Derived summary that hides closed-book writeup provenance.",
                citations=["rag:generic-method"],
                metadata={
                    "advisory_claim": True,
                    "source_refs": ["rag:generic-method", "rag:closed-book-writeup"],
                },
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
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:closed-book-writeup"], "closed_book_forbidden")
        self.assertEqual(omitted_refs["model:hidden-writeup-backed"], "invalid_citation")
        self.assertNotIn("model:hidden-writeup-backed", packet["rendered"])
        self.assertNotIn("hides closed-book writeup provenance", packet["rendered"])

    def test_ctf_solver_rejects_model_summary_citing_omitted_source_refs(self) -> None:
        envelopes = [
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
                ref="model:cited-hidden-writeup-backed",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content="Derived summary cites a forbidden source ref directly.",
                citations=["rag:closed-book-writeup"],
                metadata={"source_refs": ["rag:closed-book-writeup"]},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="ctf_solver_context",
            role="ctf_solver_orchestrator",
            target_id="lab-target",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:closed-book-writeup"], "closed_book_forbidden")
        self.assertEqual(omitted_refs["model:cited-hidden-writeup-backed"], "invalid_citation")
        self.assertNotIn("model:cited-hidden-writeup-backed", packet["rendered"])
        self.assertNotIn("forbidden source ref directly", packet["rendered"])

    def test_ctf_solver_rejects_model_summary_with_normalized_source_refs_key(self) -> None:
        envelopes = [
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
                ref="model:alias-key-hidden-writeup-backed",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content="Derived summary hides a forbidden source ref under a display-style metadata key.",
                citations=["rag:closed-book-writeup"],
                metadata={"Source Refs": ["rag:closed-book-writeup"]},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="ctf_solver_context",
            role="ctf_solver_orchestrator",
            target_id="lab-target",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:closed-book-writeup"], "closed_book_forbidden")
        self.assertEqual(omitted_refs["model:alias-key-hidden-writeup-backed"], "invalid_citation")
        self.assertNotIn("model:alias-key-hidden-writeup-backed", packet["rendered"])
        self.assertNotIn("display-style metadata key", packet["rendered"])


if __name__ == "__main__":
    unittest.main()
