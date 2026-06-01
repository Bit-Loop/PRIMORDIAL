from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart22(ContextSinkValidatorTestsBase):
    def test_prompt_sink_rejects_context_restrictions_that_exclude_prompt(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:report-only-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="planner",
                sink="prompt",
                content="Report-only advisory context must not enter prompt sinks.",
                citations=["rag:report-only-advisory"],
                valid_for=["report"],
                metadata={"valid_for": ["report"]},
            ),
            ContextEnvelope(
                ref="rag:prompt-denied-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="planner",
                sink="prompt",
                content="Prompt-denied advisory context must not enter prompt sinks.",
                citations=["rag:prompt-denied-advisory"],
                invalid_for=["prompt"],
                metadata={"invalid_for": ["prompt"]},
            ),
        ]

        result = ContextSinkValidator().validate("prompt", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:prompt-denied-advisory", "rag:report-only-advisory"])
        self.assertTrue(any("valid_for excludes prompt" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes prompt" in error for error in result.errors))

    def test_report_sink_rejects_context_restrictions_that_exclude_report(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:prompt-only-report-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="report",
                content="Prompt-only advisory context must not enter report sinks.",
                citations=["rag:prompt-only-report-advisory"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"]},
            ),
            ContextEnvelope(
                ref="rag:report-denied-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="report",
                content="Report-denied advisory context must not enter report sinks.",
                citations=["rag:report-denied-advisory"],
                invalid_for=["report"],
                metadata={"invalid_for": ["report"]},
            ),
        ]

        result = ContextSinkValidator().validate(
            "report",
            envelopes,
            known_rag_refs={"rag:prompt-only-report-advisory", "rag:report-denied-advisory"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:prompt-only-report-advisory", "rag:report-denied-advisory"])
        self.assertTrue(any("valid_for excludes report" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes report" in error for error in result.errors))

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

    def test_rag_index_rejects_nested_operational_retrieval_deny_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-operational-retrieval-denied",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested retrieval deny metadata must keep this chunk out of active RAG.",
            citations=["rag:nested-operational-retrieval-denied"],
            metadata={
                "metadata": {
                    "operational_retrieval_allowed": False,
                },
            },
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-operational-retrieval-denied"])
        self.assertTrue(any("operational_retrieval_allowed=false" in error for error in result.errors))

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

    def test_rag_index_rejects_plural_generated_export_kinds_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:plural-generated-export-kinds",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Plural generated export kind markers must not become active operational RAG.",
            citations=["rag:plural-generated-export-kinds"],
            metadata={"kinds": ["generated_export"]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:plural-generated-export-kinds"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_rag_index_rejects_generated_export_source_path(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:export-path-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Generated Notion export text must not become active operational RAG.",
                citations=["rag:export-path-advisory"],
                metadata={"source_file": "findings/notion/target-a/notion-export.md"},
            ),
            ContextEnvelope(
                ref="rag:nested-export-path-advisory",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Nested generated export paths must not become active operational RAG.",
                citations=["rag:nested-export-path-advisory"],
                metadata={"source_file": ["advisory/context.md", "generated-export.md"]},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:export-path-advisory", "rag:nested-export-path-advisory"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_rag_index_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:export-url-advisory",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Generated export URLs must not become active operational RAG.",
            citations=["rag:export-url-advisory"],
            metadata={"source_url": "https://example.invalid/findings/notion/target-a/notion-export.md"},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:export-url-advisory"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_rag_index_rejects_nested_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:nested-export-url-advisory",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Nested generated export URLs must not become active operational RAG.",
            citations=["rag:nested-export-url-advisory"],
            metadata={
                "provenance": {
                    "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md"
                }
            },
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-export-url-advisory"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_rag_index_rejects_quarantined_markdown_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:quarantined-markdown-url",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Quarantined Markdown must not become active operational RAG.",
            citations=["rag:quarantined-markdown-url"],
            metadata={
                "source_url": "https://example.invalid/runtime/quarantine/markdown/docs/RAG_SRC/0x11-t10.md"
            },
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:quarantined-markdown-url"])
        self.assertTrue(any("source Markdown" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart22"]
