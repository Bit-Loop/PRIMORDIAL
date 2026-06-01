from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart19(ContextSinkValidatorTestsBase):
    def test_notion_export_quarantines_masked_nested_non_evidence_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="evidence:masked-model-export-proof",
            kind="evidence",
            authority="observed",
            source_type="tool_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Top-level evidence source type must not mask nested model provenance.",
            citations=["evidence:masked-model-export-proof"],
            metadata={
                "metadata": {
                    "source_type": "ai_output",
                },
            },
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["evidence:masked-model-export-proof"])
        self.assertTrue(any("source_type=ai_output" in error for error in result.errors))

    def test_notion_export_quarantines_nested_raw_chat_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:export-nested-chat-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="export",
            sink="notion_export",
            content="Top-level methodology metadata must not mask nested chat provenance.",
            citations=["rag:export-nested-chat-source"],
            metadata={
                "metadata": {
                    "source_type": "chat",
                },
            },
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_rag_refs={"rag:export-nested-chat-source"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["rag:export-nested-chat-source"])
        self.assertTrue(any("raw chat context" in error for error in result.errors))

    def test_direct_notion_export_quarantines_plural_nested_raw_chat_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:direct-export-plural-chat-source",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="export",
            sink="notion_export",
            content="Top-level methodology source type must not mask plural nested chat provenance.",
            citations=["rag:direct-export-plural-chat-source"],
            metadata={
                "metadata": {
                    "source_types": ["chat"],
                },
            },
        )

        decision = validate_notion_export_envelope(
            envelope,
            set(),
            known_rag_refs={"rag:direct-export-plural-chat-source"},
        )

        self.assertEqual(decision.action, "quarantine")
        self.assertIn("raw chat context", decision.message)

    def test_notion_export_quarantines_generated_export_source_path(self) -> None:
        envelope = ContextEnvelope(
            ref="model:export-path-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="A model summary sourced from a prior Notion export must not feed a fresh export.",
            citations=["evidence:scan-1"],
            metadata={
                "source_file": "findings/notion/target-a/notion-export.md",
                "source_refs": ["evidence:scan-1"],
            },
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_evidence_refs={"evidence:scan-1"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:export-path-summary"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_notion_export_quarantines_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="model:export-url-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="A model summary sourced from a prior export URL must not feed a fresh export.",
            citations=["evidence:scan-1"],
            metadata={
                "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
                "source_refs": ["evidence:scan-1"],
            },
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_evidence_refs={"evidence:scan-1"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:export-url-summary"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_notion_export_quarantines_nested_ai_summary_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-export-source-ref-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Nested export provenance must not hide unsupported source references.",
            citations=["evidence:http-banner"],
            metadata={
                "metadata": {
                    "source_refs": ["evidence:http-banner", "github:issue-42"],
                }
            },
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:nested-export-source-ref-summary"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_notion_export_quarantines_nested_truth_like_authority_on_ai_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-export-confirmed-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Nested metadata must not let AI-derived export context claim confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"authority": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:nested-export-confirmed-summary"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_notion_export_quarantines_plural_nested_truth_like_authorities_on_ai_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:nested-export-confirmed-authorities-summary",
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="export",
            sink="notion_export",
            content="Nested plural metadata must not let AI-derived export context claim confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={
                "source_refs": ["evidence:http-banner"],
                "metadata": {"authorities": ["confirmed"]},
            },
        )

        result = ContextSinkValidator().validate(
            "notion_export",
            [envelope],
            known_evidence_refs={"evidence:http-banner"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["model:nested-export-confirmed-authorities-summary"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_notion_export_quarantines_rag_with_unsupported_source_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:export-unsupported-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="export",
            sink="notion_export",
            content="Export RAG context must not hide unsupported provenance.",
            citations=["rag:export-unsupported-source-refs"],
            metadata={"source_refs": ["github:issue-42"]},
        )

        result = ContextSinkValidator().validate("notion_export", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.quarantined_refs, ["rag:export-unsupported-source-refs"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart19"]
