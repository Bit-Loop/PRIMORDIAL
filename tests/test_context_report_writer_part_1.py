from __future__ import annotations

from tests.test_context_report_writer_common import *


class ContextReportWriterTestsPart1(ContextReportWriterTestsBase):
    def test_report_writer_omits_hidden_flags_and_secret_material_from_prompt_context(self) -> None:
        envelopes = [
            self._envelope("evidence:http", "evidence", "tool_output", "Observed HTTP evidence.", ["evidence:http"]),
            self._envelope("finding:web-1", "finding", "runtime_state", "Reviewed finding.", ["evidence:http"]),
            self._envelope(
                "ctfd:raw-flag",
                "ctfd_ref",
                "ctfd",
                "Raw captured flag must not enter report-writer prompt context.",
                [],
                contains_raw_flag=True,
            ),
            self._envelope(
                "rag:hidden-solution",
                "rag",
                "writeup",
                "Hidden solution sequence must not enter report-writer prompt context.",
                ["rag:hidden-solution"],
                hidden_solution_material=True,
            ),
            self._envelope(
                "note:secret",
                "operator_note",
                "manual_artifact",
                "Unredacted secret must not enter report-writer prompt context.",
                ["note:secret"],
                contains_secret=True,
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["REVIEWED_FINDINGS"]], ["finding:web-1"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["ctfd:raw-flag"], "sensitive_material")
        self.assertEqual(omitted_refs["rag:hidden-solution"], "sensitive_material")
        self.assertEqual(omitted_refs["note:secret"], "sensitive_material")
        rendered = packet["rendered"]
        self.assertIn("Reviewed finding.", rendered)
        self.assertNotIn("Raw captured flag", rendered)
        self.assertNotIn("Hidden solution sequence", rendered)
        self.assertNotIn("Unredacted secret", rendered)

    def test_report_writer_rejects_model_summary_backed_by_active_postmortem_only_writeup(self) -> None:
        envelopes = [
            self._envelope(
                "rag:generic-report-method",
                "rag",
                "methodology_doc",
                "Generic reporting guidance is allowed as advisory context.",
                ["rag:generic-report-method"],
            ),
            self._envelope(
                "rag:postmortem-only-writeup",
                "rag",
                "writeup",
                "Postmortem-only writeup content must not enter active report prompts.",
                ["rag:postmortem-only-writeup"],
                writeup_access_policy="postmortem_only",
            ),
            self._envelope(
                "model:generic-report-method",
                "model_summary",
                "ai_output",
                "Derived report guidance based on generic methodology.",
                ["rag:generic-report-method"],
                advisory_claim=True,
            ),
            self._envelope(
                "model:postmortem-only-backed",
                "model_summary",
                "ai_output",
                "Derived report prose based on postmortem-only writeup material.",
                ["rag:postmortem-only-writeup"],
                advisory_claim=True,
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:generic-report-method"])
        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:generic-report-method"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:postmortem-only-writeup"], "postmortem_only_forbidden")
        self.assertEqual(omitted_refs["model:postmortem-only-backed"], "invalid_citation")
        self.assertNotIn("model:postmortem-only-backed", packet["rendered"])

    def test_report_writer_rejects_model_summary_backed_by_closed_book_writeup(self) -> None:
        envelopes = [
            self._envelope(
                "rag:generic-report-method",
                "rag",
                "methodology_doc",
                "Generic reporting guidance is allowed as advisory context.",
                ["rag:generic-report-method"],
            ),
            self._envelope(
                "rag:closed-book-writeup",
                "rag",
                "writeup",
                "Closed-book writeup content must not enter active report prompts.",
                ["rag:closed-book-writeup"],
                benchmark_mode="closed_book",
            ),
            self._envelope(
                "model:generic-report-method",
                "model_summary",
                "ai_output",
                "Derived report guidance based on generic methodology.",
                ["rag:generic-report-method"],
                advisory_claim=True,
            ),
            self._envelope(
                "model:closed-book-backed",
                "model_summary",
                "ai_output",
                "Derived report prose based on closed-book writeup material.",
                ["rag:closed-book-writeup"],
                advisory_claim=True,
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:generic-report-method"])
        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:generic-report-method"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:closed-book-writeup"], "closed_book_forbidden")
        self.assertEqual(omitted_refs["model:closed-book-backed"], "invalid_citation")
        self.assertNotIn("model:closed-book-backed", packet["rendered"])

    def test_report_writer_rejects_model_summary_backed_by_writeups_disabled_metadata(self) -> None:
        envelopes = [
            self._envelope(
                "rag:generic-report-method",
                "rag",
                "methodology_doc",
                "Generic reporting guidance is allowed as advisory context.",
                ["rag:generic-report-method"],
            ),
            self._envelope(
                "rag:writeups-disabled",
                "rag",
                "writeup",
                "Writeup content with writeups disabled must not enter active report prompts.",
                ["rag:writeups-disabled"],
                writeups_allowed=False,
            ),
            self._envelope(
                "model:generic-report-method",
                "model_summary",
                "ai_output",
                "Derived report guidance based on generic methodology.",
                ["rag:generic-report-method"],
                advisory_claim=True,
            ),
            self._envelope(
                "model:writeups-disabled-backed",
                "model_summary",
                "ai_output",
                "Derived report prose based on writeup content that policy disabled.",
                ["rag:writeups-disabled"],
                advisory_claim=True,
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:generic-report-method"])
        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:generic-report-method"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:writeups-disabled"], "writeups_forbidden")
        self.assertEqual(omitted_refs["model:writeups-disabled-backed"], "invalid_citation")
        self.assertNotIn("model:writeups-disabled-backed", packet["rendered"])

    def test_report_writer_rejects_model_summary_backed_by_forbidden_writeup_policy(self) -> None:
        envelopes = [
            self._envelope(
                "rag:generic-report-method",
                "rag",
                "methodology_doc",
                "Generic reporting guidance is allowed as advisory context.",
                ["rag:generic-report-method"],
            ),
            self._envelope(
                "rag:forbidden-writeup",
                "rag",
                "writeup",
                "Writeup content with a forbidden policy must not enter active report prompts.",
                ["rag:forbidden-writeup"],
                writeup_access_policy="forbidden",
            ),
            self._envelope(
                "model:generic-report-method",
                "model_summary",
                "ai_output",
                "Derived report guidance based on generic methodology.",
                ["rag:generic-report-method"],
                advisory_claim=True,
            ),
            self._envelope(
                "model:forbidden-writeup-backed",
                "model_summary",
                "ai_output",
                "Derived report prose based on writeup content that policy forbids.",
                ["rag:forbidden-writeup"],
                advisory_claim=True,
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:generic-report-method"])
        self.assertEqual([item["ref"] for item in packet["sections"]["MODEL_DERIVED"]], ["model:generic-report-method"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:forbidden-writeup"], "writeups_forbidden")
        self.assertEqual(omitted_refs["model:forbidden-writeup-backed"], "invalid_citation")
        self.assertNotIn("model:forbidden-writeup-backed", packet["rendered"])

__all__ = ["ContextReportWriterTestsPart1"]
