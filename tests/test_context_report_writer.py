from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope, ContextSinkValidator


class ContextReportWriterTests(unittest.TestCase):
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

    def test_report_sink_rejects_ai_summary_with_only_collaboration_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:github-only-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="AI-derived report context must not be backed only by collaboration prose.",
            citations=["github:issue-42"],
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:github-only-summary"])
        self.assertTrue(any("evidence:<id>, note:<id>, or rag:<chunk_id>" in error for error in result.errors))

    def test_report_sink_rejects_ai_summary_with_mixed_collaboration_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:github-mixed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="AI-derived report context must not mix evidence with collaboration provenance.",
            citations=["evidence:http-banner", "github:issue-42"],
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:github-mixed-summary"])
        self.assertTrue(any("unsupported citations" in error for error in result.errors))
        self.assertTrue(any("github:issue-42" in error for error in result.errors))

    def test_report_sink_rejects_truth_like_authority_on_ai_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:confirmed-summary",
            kind="model_summary",
            authority="confirmed",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="AI-derived report context must not claim confirmed target truth.",
            citations=["evidence:http-banner"],
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:confirmed-summary"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_report_sink_rejects_nested_truth_like_authority_on_ai_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-confirmed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="Nested metadata must not let AI-derived report context claim confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"authority": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:nested-confirmed-summary"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_report_sink_rejects_plural_nested_truth_like_authorities_on_ai_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-confirmed-authorities-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="Nested plural metadata must not let AI-derived report context claim confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"authorities": ["confirmed"]},
            },
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:nested-confirmed-authorities-summary"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_report_sink_rejects_generated_export_recursion(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="model:generated-export-report-summary",
                kind="model_summary",
                authority="derived",
                source_type="generated_export",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="A previous generated export must not feed report output as model prose.",
                citations=["evidence:http-banner"],
            ),
            ContextEnvelope(
                ref="model:export-origin-report-summary",
                kind="model_summary",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="AI prose derived from a generated export must not feed report output.",
                citations=["evidence:http-banner"],
                metadata={"origin": "generated export"},
            ),
        ]

        result = ContextSinkValidator().validate(
            "report",
            envelopes,
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["model:export-origin-report-summary", "model:generated-export-report-summary"],
        )
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_report_sink_rejects_generated_export_source_path(self) -> None:
        envelope = ContextEnvelope(
            ref="model:export-path-report-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="report_generation",
            sink="report",
            content="AI prose sourced from a generated Notion export must not feed report output.",
            citations=["evidence:http-banner"],
            metadata={
                "source_file": "findings/notion/target-a/notion-export.md",
                "source_refs": ["evidence:http-banner"],
            },
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:export-path-report-summary"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_report_sink_rejects_non_evidence_sources_from_evidence_records(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:scan-1",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Observed scanner output is valid report evidence.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="evidence:notion-projection",
                kind="evidence",
                authority="observed",
                source_type="notion",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Notion projection must not render as report evidence.",
                citations=["evidence:notion-projection"],
            ),
            ContextEnvelope(
                ref="evidence:github-issue",
                kind="evidence",
                authority="observed",
                source_type="github",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="GitHub issue prose must not render as report evidence.",
                citations=["evidence:github-issue"],
            ),
            ContextEnvelope(
                ref="evidence:ctfd-challenge",
                kind="evidence",
                authority="observed",
                source_type="ctfd",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="CTFd challenge metadata must not render as report evidence.",
                citations=["evidence:ctfd-challenge"],
            ),
            ContextEnvelope(
                ref="evidence:vuln-intel",
                kind="evidence",
                authority="observed",
                source_type="vuln_intel",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Vulnerability intelligence must remain advisory in reports.",
                citations=["evidence:vuln-intel"],
            ),
            ContextEnvelope(
                ref="evidence:ai-summary",
                kind="evidence",
                authority="observed",
                source_type="ai_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Model output must not render as report evidence.",
                citations=["evidence:ai-summary"],
            ),
        ]

        result = ContextSinkValidator().validate("report", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:scan-1"])
        self.assertEqual(
            result.rejected_refs,
            [
                "evidence:ai-summary",
                "evidence:ctfd-challenge",
                "evidence:github-issue",
                "evidence:notion-projection",
                "evidence:vuln-intel",
            ],
        )
        for source_type in ("ai_output", "ctfd", "github", "notion", "vuln_intel"):
            self.assertTrue(any(f"source_type={source_type}" in error for error in result.errors), source_type)

    def test_report_sink_rejects_malformed_evidence_records(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="evidence:scan-1",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Observed scanner output is valid report evidence.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="evidence:advisory-proof",
                kind="evidence",
                authority="advisory",
                source_type="tool_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Advisory authority must not render as report evidence.",
                citations=["evidence:advisory-proof"],
            ),
            ContextEnvelope(
                ref="model:evidence-shaped",
                kind="evidence",
                authority="observed",
                source_type="tool_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="A non-evidence ref must not render as report evidence.",
                citations=["evidence:scan-1"],
            ),
        ]

        result = ContextSinkValidator().validate("report", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["evidence:scan-1"])
        self.assertEqual(result.rejected_refs, ["evidence:advisory-proof", "model:evidence-shaped"])
        self.assertTrue(any("rejects evidence authority=advisory" in error for error in result.errors))
        self.assertTrue(any("requires evidence:<id> ref" in error for error in result.errors))

    def test_report_sink_rejects_non_evidence_sources_from_reviewed_findings(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="finding:runtime",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Runtime-reviewed finding belongs in reports.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="finding:notion-projection",
                kind="finding",
                authority="reviewed",
                source_type="notion",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Notion projection must not render as a reviewed report finding.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="finding:github-issue",
                kind="finding",
                authority="reviewed",
                source_type="github",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="GitHub issue prose must not render as a reviewed report finding.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="finding:ai-summary",
                kind="finding",
                authority="reviewed",
                source_type="ai_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Model output must not render as a reviewed report finding.",
                citations=["evidence:scan-1"],
            ),
        ]

        result = ContextSinkValidator().validate("report", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["finding:runtime"])
        self.assertEqual(
            result.rejected_refs,
            ["finding:ai-summary", "finding:github-issue", "finding:notion-projection"],
        )
        for source_type in ("ai_output", "github", "notion"):
            self.assertTrue(any(f"source_type={source_type}" in error for error in result.errors), source_type)

    def test_report_sink_rejects_masked_nested_non_evidence_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:masked-model-proof",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="Top-level evidence source type must not mask nested model provenance.",
            citations=["evidence:masked-model-proof"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["evidence:masked-model-proof"])
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))

    def test_report_sink_rejects_ai_output_disguised_as_operator_note(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="note:manual-operator",
                kind="operator_note",
                authority="asserted",
                source_type="manual_artifact",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Human operator notes may provide report context.",
                citations=["note:manual-operator"],
            ),
            ContextEnvelope(
                ref="note:model-generated",
                kind="operator_note",
                authority="asserted",
                source_type="ai_output",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Model prose must not masquerade as an operator note in report context.",
                citations=["note:model-generated"],
            ),
        ]

        result = ContextSinkValidator().validate("report", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["note:manual-operator"])
        self.assertEqual(result.rejected_refs, ["note:model-generated"])
        self.assertTrue(any("non_operator_note_source" in error for error in result.errors))

    def test_report_sink_rejects_finding_shaped_records_without_finding_refs(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="finding:runtime",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="Runtime-reviewed finding belongs in reports.",
                citations=["evidence:scan-1"],
            ),
            ContextEnvelope(
                ref="model:finding-shaped",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                target_id="target-a",
                purpose="report_generation",
                sink="report",
                content="A non-finding ref must not render as a reviewed report finding.",
                citations=["evidence:scan-1"],
            ),
        ]

        result = ContextSinkValidator().validate("report", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["finding:runtime"])
        self.assertEqual(result.rejected_refs, ["model:finding-shaped"])
        self.assertTrue(any("finding:<id>" in error for error in result.errors))

    def test_report_writer_omits_unbound_model_target_fact_from_current_packet(self) -> None:
        envelope = ContextEnvelope(
            ref="model:unbound-target-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="report_generation",
            sink="prompt",
            content="The target reports nginx in the HTTP banner.",
            citations=["evidence:http-banner"],
            metadata={"contains_target_fact": True},
        )

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["model:unbound-target-summary"], "missing_target_binding")
        self.assertNotIn("nginx", packet["rendered"])

    def test_report_writer_omits_unbound_reviewed_findings_from_current_packet(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="finding:no-target",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                active_generation_id="generation:2",
                purpose="report_generation",
                sink="prompt",
                content="Unbound reviewed finding must not enter a current target report.",
                citations=["evidence:http-banner"],
            ),
            ContextEnvelope(
                ref="finding:no-generation",
                kind="finding",
                authority="reviewed",
                source_type="runtime_state",
                target_id="target-a",
                purpose="report_generation",
                sink="prompt",
                content="Generationless reviewed finding must not enter a current target report.",
                citations=["evidence:http-banner"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="report_generation",
            role="report_writer",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["REVIEWED_FINDINGS"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["finding:no-target"], "missing_target_binding")
        self.assertEqual(omitted_refs["finding:no-generation"], "missing_generation_binding")
        self.assertNotIn("Unbound reviewed finding", packet["rendered"])
        self.assertNotIn("Generationless reviewed finding", packet["rendered"])

    def _envelope(
        self,
        ref: str,
        kind: str,
        source_type: str,
        content: str,
        citations: list[str],
        **metadata: object,
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind=kind,
            authority="reviewed" if kind == "finding" else "asserted",
            source_type=source_type,
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="report_generation",
            sink="prompt",
            content=content,
            citations=citations,
            metadata=metadata,
        )


if __name__ == "__main__":
    unittest.main()
