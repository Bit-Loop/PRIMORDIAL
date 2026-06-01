from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart25(ContextSinkValidatorTestsBase):
    def test_rag_index_rejects_plural_nested_collaboration_reference_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-github-ref-kinds",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested plural kind metadata must not let collaboration references become active RAG.",
            citations=["rag:nested-github-ref-kinds"],
            metadata={"metadata": {"kinds": ["github_ref"]}},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-github-ref-kinds"])
        self.assertTrue(any("collaboration reference lane material" in error for error in result.errors))

    def test_rag_index_rejects_plural_nested_recent_action_trace_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-action-trace-kinds",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested plural kind metadata must not let recent action traces become active RAG.",
            citations=["rag:nested-action-trace-kinds"],
            metadata={"metadata": {"kinds": ["action_trace"]}},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-action-trace-kinds"])
        self.assertTrue(any("recent action trace lane material" in error for error in result.errors))

    def test_rag_index_rejects_plural_nested_non_advisory_source_types(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-manual-artifact-source-types",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested plural source type metadata must not let non-advisory material become active RAG.",
            citations=["rag:nested-manual-artifact-source-types"],
            metadata={"metadata": {"source_types": ["manual_artifact"]}},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-manual-artifact-source-types"])
        self.assertTrue(any("requires advisory source_type" in error for error in result.errors))

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

    def test_report_sink_rejects_nested_ai_summary_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-report-source-ref-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="Nested report provenance must not hide unsupported source references.",
            citations=["evidence:http-banner"],
            metadata={
                "metadata": {
                    "source_refs": ["evidence:http-banner", "github:issue-42"],
                }
            },
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:nested-report-source-ref-summary"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_report_sink_rejects_placeholder_ai_summary_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="model:placeholder-report-citation-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="report_generation",
            sink="report",
            content="Placeholder citations must not satisfy report provenance.",
            citations=["note:null"],
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:placeholder-report-citation-summary"])
        self.assertTrue(any("placeholder" in error for error in result.errors))
        self.assertTrue(any("note:null" in error for error in result.errors))

    def test_report_sink_rejects_nested_raw_chat_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:report-nested-chat-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="report_generation",
            sink="report",
            content="Top-level methodology metadata must not mask nested chat provenance.",
            citations=["rag:report-nested-chat-source"],
            metadata={
                "metadata": {
                    "source_type": "chat",
                },
            },
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_rag_refs={"rag:report-nested-chat-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:report-nested-chat-source"])
        self.assertTrue(any("raw chat context" in error for error in result.errors))

    def test_direct_report_sink_rejects_plural_nested_raw_chat_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:direct-report-plural-chat-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="report_generation",
            sink="report",
            content="Top-level methodology source type must not mask plural nested chat provenance.",
            citations=["rag:direct-report-plural-chat-source"],
            metadata={
                "metadata": {
                    "source_types": ["chat"],
                },
            },
        )

        decision = validate_report_sink(envelope)

        self.assertEqual(decision.action, "reject")
        self.assertIn("raw chat context", decision.message)

    def test_report_sink_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:report-export-url",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="report_generation",
            sink="report",
            content="Generated export URLs must not recurse into report context.",
            citations=["rag:report-export-url"],
            metadata={"source_url": "https://example.invalid/findings/notion/target-a/notion-export.md"},
        )

        result = ContextSinkValidator().validate(
            "report",
            [envelope],
            known_rag_refs={"rag:report-export-url"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:report-export-url"])
        self.assertTrue(any("generated export" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart25"]
