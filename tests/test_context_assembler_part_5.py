from __future__ import annotations

from tests.test_context_assembler_common import *


class ContextAssemblerTestsPart5(ContextAssemblerTestsBase):
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

__all__ = [name for name in globals() if name.endswith("Part5")]
