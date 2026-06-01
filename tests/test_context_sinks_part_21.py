from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart21(ContextSinkValidatorTestsBase):
    def test_notion_inbox_rejects_plural_nested_unsupported_source_types(self) -> None:
        envelope = ContextEnvelope(
            ref="note:inbox-nested-ai-output-source",
            kind="external_reference",
            authority="advisory",
            source_type="notion",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="Inbound Notion source metadata must not mask nested model output provenance.",
            citations=["note:inbox-nested-ai-output-source"],
            metadata={
                "edit_source": "user",
                "metadata": {"source_types": ["ai_output"]},
            },
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:inbox-nested-ai-output-source"])
        self.assertTrue(any("unsupported source_type=ai_output" in error for error in result.errors))

    def test_notion_inbox_rejects_masked_nested_confirmed_finding_status(self) -> None:
        envelope = ContextEnvelope(
            ref="note:inbox-masked-confirmed-finding",
            kind="finding_draft_delta",
            authority="advisory",
            source_type="notion",
            target_id="target-a",
            purpose="notion_inbox",
            sink="notion_inbox",
            content="Top-level draft status must not mask nested confirmed finding status.",
            citations=["note:inbox-masked-confirmed-finding"],
            metadata={
                "edit_source": "user",
                "finding_status": "draft",
                "metadata": {"finding_status": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate("notion_inbox", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:inbox-masked-confirmed-finding"])
        self.assertTrue(any("confirmed finding" in error for error in result.errors))

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

    def test_rag_index_rejects_list_valued_hidden_solution_metadata_flag(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:list-hidden-solution",
            kind="rag",
            authority="advisory",
            source_type="ctf_manifest",
            purpose="ctf_benchmark",
            sink="rag_index",
            content="List-valued hidden solution markers must not enter active operational RAG.",
            citations=["rag:list-hidden-solution"],
            metadata={"hidden_solution_material": [False, True]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:list-hidden-solution"])
        self.assertTrue(any("hidden solution material" in error for error in result.errors))

    def test_rag_index_rejects_metadata_poison_flags_list_values(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:metadata-poison-flags-hidden-solution",
            kind="rag",
            authority="advisory",
            source_type="ctf_manifest",
            purpose="ctf_benchmark",
            sink="rag_index",
            content="Metadata poison_flags values must not hide hidden solution material from RAG.",
            citations=["rag:metadata-poison-flags-hidden-solution"],
            metadata={"poison_flags": ["hidden_solution_material"]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:metadata-poison-flags-hidden-solution"])
        self.assertTrue(any("hidden solution material" in error for error in result.errors))

    def test_rag_index_rejects_human_readable_metadata_poison_flag_value(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:human-readable-poison-flag-hidden-solution",
            kind="rag",
            authority="advisory",
            source_type="ctf_manifest",
            purpose="ctf_benchmark",
            sink="rag_index",
            content="Human-readable poison flag metadata must not hide hidden solution material from RAG.",
            citations=["rag:human-readable-poison-flag-hidden-solution"],
            metadata={"Poison flag": "hidden_solution_material"},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:human-readable-poison-flag-hidden-solution"])
        self.assertTrue(any("hidden solution material" in error for error in result.errors))

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

    def test_rag_index_rejects_context_restrictions_that_exclude_rag_index(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:prompt-only-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Prompt-only advisory context must not be indexed into active RAG.",
                citations=["rag:prompt-only-advisory"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"]},
            ),
            ContextEnvelope(
                ref="rag:rag-index-denied-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="RAG-index-denied advisory context must not be indexed into active RAG.",
                citations=["rag:rag-index-denied-advisory"],
                invalid_for=["rag_index"],
                metadata={"invalid_for": ["rag_index"]},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:prompt-only-advisory", "rag:rag-index-denied-advisory"])
        self.assertTrue(any("valid_for excludes rag_index" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes rag_index" in error for error in result.errors))

    def test_rag_index_honors_purpose_context_restrictions(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:cleanup-denied-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Cleanup-denied advisory context must not enter the cleanup RAG index context.",
                citations=["rag:cleanup-denied-advisory"],
                invalid_for=["cleanup"],
                metadata={"invalid_for": ["cleanup"]},
            ),
            ContextEnvelope(
                ref="rag:cleanup-only-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Cleanup-only advisory context may enter the cleanup RAG index context.",
                citations=["rag:cleanup-only-advisory"],
                valid_for=["cleanup"],
                metadata={"valid_for": ["cleanup"]},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:cleanup-only-advisory"])
        self.assertEqual(result.rejected_refs, ["rag:cleanup-denied-advisory"])
        self.assertTrue(any("invalid_for excludes rag_index" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart21"]
