from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart26(ContextSinkValidatorTestsBase):
    def test_report_sink_rejects_nested_writeups_disabled_writeup(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:report-writeups-disabled",
            kind="rag",
            authority="advisory",
            source_type="writeup",
            purpose="report_generation",
            sink="report",
            content="Report generation must not use writeup-denied material.",
            citations=["rag:report-writeups-disabled"],
            metadata={"metadata": {"writeups_allowed": False}},
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_rag_refs={"rag:report-writeups-disabled"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:report-writeups-disabled"])
        self.assertTrue(any("writeups_forbidden" in error for error in result.errors))

    def test_report_sink_rejects_masked_nested_closed_book_writeup_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:report-masked-closed-book-writeup",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="report_generation",
            sink="report",
            content="Nested writeup source metadata must not be masked as methodology in closed-book reports.",
            citations=["rag:report-masked-closed-book-writeup"],
            metadata={"metadata": {"source_types": ["writeup"], "benchmark_mode": "closed_book"}},
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_rag_refs={"rag:report-masked-closed-book-writeup"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:report-masked-closed-book-writeup"])
        self.assertTrue(any("closed_book_forbidden" in error for error in result.errors))

    def test_report_sink_rejects_list_valued_writeup_policy_metadata(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:report-list-closed-book-writeup",
                kind="rag",
                authority="advisory",
                source_type="writeup",
                purpose="report_generation",
                sink="report",
                content="List-valued benchmark metadata must not hide closed-book writeups.",
                citations=["rag:report-list-closed-book-writeup"],
                metadata={"benchmark_mode": ["open_book", "closed_book"]},
            ),
            ContextEnvelope(
                ref="rag:report-list-postmortem-only-writeup",
                kind="rag",
                authority="advisory",
                source_type="writeup",
                purpose="report_generation",
                sink="report",
                content="List-valued policy metadata must not hide postmortem-only writeups.",
                citations=["rag:report-list-postmortem-only-writeup"],
                metadata={"writeup_access_policy": ["allowed", "postmortem_only"]},
            ),
            ContextEnvelope(
                ref="rag:report-list-writeups-disabled",
                kind="rag",
                authority="advisory",
                source_type="writeup",
                purpose="report_generation",
                sink="report",
                content="List-valued writeups_allowed metadata must not hide disabled writeups.",
                citations=["rag:report-list-writeups-disabled"],
                metadata={"writeups_allowed": [True, False]},
            ),
        ]

        result = ContextSinkValidator().validate(
            "report",
            envelopes,
            known_rag_refs={envelope.ref for envelope in envelopes},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            [
                "rag:report-list-closed-book-writeup",
                "rag:report-list-postmortem-only-writeup",
                "rag:report-list-writeups-disabled",
            ],
        )
        self.assertTrue(any("closed_book_forbidden" in error for error in result.errors))
        self.assertTrue(any("postmortem_only_forbidden" in error for error in result.errors))
        self.assertTrue(any("writeups_forbidden" in error for error in result.errors))

    def test_report_sink_rejects_model_refs_against_rejected_operator_note(self) -> None:
        note = ContextEnvelope(
            ref="note:bad-report-provenance",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="report_generation",
            sink="report",
            content="Report note provenance must not cite unresolved evidence.",
            citations=["note:bad-report-provenance", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )
        model_summary = ContextEnvelope(
            ref="model:bad-report-note-backed",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="report_generation",
            sink="report",
            content="Report model output must not resolve against a rejected operator note.",
            citations=["note:bad-report-provenance"],
            metadata={"source_refs": ["note:bad-report-provenance"]},
        )

        result = ContextSinkValidator().validate("report", [note, model_summary], known_evidence_refs=set())

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:bad-report-note-backed", "note:bad-report-provenance"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))

    def test_report_sink_rejects_rag_with_unsupported_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:report-unsupported-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="report_generation",
            sink="report",
            content="Report RAG context must not hide unsupported provenance.",
            citations=["rag:report-unsupported-source-refs"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:report-unsupported-source-refs"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_direct_report_sink_rejects_rag_with_unsupported_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:direct-report-unsupported-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="report_generation",
            sink="report",
            content="Direct report validation must not let RAG hide unsupported provenance.",
            citations=["rag:direct-report-unsupported-source-refs"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        decision = validate_report_sink(envelope)

        self.assertEqual(decision.action, "reject")
        self.assertIn("unsupported source_refs", decision.message)
        self.assertIn("github:issue-42", decision.message)

    def test_direct_report_sink_rejects_operator_note_with_unsupported_source_refs(self) -> None:
        note = ContextEnvelope(
            ref="note:direct-report-unsupported-source-refs",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="report_generation",
            sink="report",
            content="Direct report validation must not let operator notes hide unsupported provenance.",
            citations=["note:direct-report-unsupported-source-refs"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        decision = validate_report_sink(note)

        self.assertEqual(decision.action, "reject")
        self.assertIn("unsupported source_refs", decision.message)
        self.assertIn("github:issue-42", decision.message)

    def test_report_sink_rejects_rag_with_unresolved_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:report-unresolved-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="report_generation",
            sink="report",
            content="Report RAG context must not cite unresolved evidence provenance.",
            citations=["rag:report-unresolved-source-refs", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_evidence_refs=set(),
            known_rag_refs={"rag:report-unresolved-source-refs"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:report-unresolved-source-refs"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart26"]
