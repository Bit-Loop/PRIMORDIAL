from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator

from primordial.core.context.collaboration import validate_collaboration_sink

from primordial.core.context.metadata_flags import metadata_value_is_false, raw_metadata_value

from primordial.core.context.notion_export import validate_notion_export_envelope

from primordial.core.context.report import validate_report_sink

class ContextSinkValidatorTestsBase(unittest.TestCase):
    pass

class ContextNormalizationTests(unittest.TestCase):
    def test_canonical_rag_domain_normalizes_shared_aliases(self) -> None:
        from primordial.core.context.normalization import canonical_rag_domain

        self.assertEqual(canonical_rag_domain("HTB Writeup"), "htb_writeup")
        self.assertEqual(canonical_rag_domain("API Web"), "api_security")
        self.assertEqual(canonical_rag_domain("vulnerability_intel"), "vuln_intel")
        self.assertEqual(canonical_rag_domain("future-domain"), "general_security")

    def test_metadata_helpers_preserve_human_readable_values(self) -> None:
        from primordial.core.context.normalization import metadata_bool_value, metadata_list_value, metadata_value

        metadata = {
            "Source trust": "official_feed",
            "CVE IDs": ("CVE-2026-0001", "CVE-2026-0002"),
            "Walkthrough hint": "yes",
        }

        self.assertEqual(metadata_value(metadata, "source_trust"), "official_feed")
        self.assertEqual(metadata_list_value(metadata, "cve_ids"), ["CVE-2026-0001", "CVE-2026-0002"])
        self.assertTrue(metadata_bool_value(metadata, "walkthrough_hint"))

    def test_rag_envelope_preserves_human_readable_binding_metadata(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "display-binding",
                "text": "Advisory context with display metadata.",
                "metadata": {
                    "Target ID": "target-a",
                    "Active generation ID": "generation:2",
                    "Corpus type": "vuln_intel",
                    "Domain": "vuln_intel",
                    "Valid for": ("planner", "vuln_hint_for_target"),
                    "Invalid for": "evidence",
                    "Poison flags": ("generated_export",),
                },
            },
            purpose="planner",
            sink="prompt",
        )

        self.assertEqual(envelope.target_id, "target-a")
        self.assertEqual(envelope.active_generation_id, "generation:2")
        self.assertEqual(envelope.corpus, "vuln_intel")
        self.assertEqual(envelope.domain, "vuln_intel")
        self.assertEqual(envelope.valid_for, ["planner", "vuln_hint_for_target"])
        self.assertEqual(envelope.invalid_for, ["evidence"])
        self.assertEqual(envelope.poison_flags, ["generated_export"])

    def test_rag_envelope_preserves_human_readable_citation_id(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "display-citation-chunk",
                "text": "Advisory context with display-key citation metadata.",
                "metadata": {
                    "Citation ID": "display-citation-source",
                    "Corpus type": "vuln_intel",
                    "Domain": "vuln_intel",
                },
            },
            purpose="planner",
            sink="prompt",
        )

        self.assertEqual(envelope.ref, "rag:display-citation-source")
        self.assertEqual(envelope.citations, ["rag:display-citation-source"])

    def test_rag_envelope_preserves_human_readable_retrieval_text(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "display-retrieval-text",
                "metadata": {
                    "Retrieval text": "Display-key advisory RAG text must remain envelope content.",
                    "Citation ID": "display-retrieval-source",
                    "Corpus type": "methodology_standards",
                    "Domain": "methodology_standards",
                },
            },
            purpose="operator_answer",
            sink="prompt",
        )

        self.assertEqual(envelope.content, "Display-key advisory RAG text must remain envelope content.")
        self.assertEqual(envelope.ref, "rag:display-retrieval-source")

    def test_rag_envelope_preserves_human_readable_raw_text(self) -> None:
        envelope = ContextEnvelope.from_rag_chunk(
            {
                "chunk_id": "display-raw-text",
                "metadata": {
                    "Raw text": "Display-key raw RAG text must remain envelope content.",
                    "Citation ID": "display-raw-source",
                    "Corpus type": "methodology_standards",
                    "Domain": "methodology_standards",
                },
            },
            purpose="operator_answer",
            sink="prompt",
        )

        self.assertEqual(envelope.content, "Display-key raw RAG text must remain envelope content.")
        self.assertEqual(envelope.ref, "rag:display-raw-source")

__all__ = [name for name in globals() if not name.startswith("__")]
