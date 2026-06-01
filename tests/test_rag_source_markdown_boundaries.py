from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class RagSourceMarkdownBoundaryTests(unittest.TestCase):
    def test_rag_index_rejects_legacy_source_markdown_drop_paths(self) -> None:
        envelopes = [
            self._rag("rag:accepted-methodology", source_type="methodology_doc"),
            self._rag(
                "rag:legacy-rag-src",
                source_type="validated_external",
                metadata={"source_file": "docs/RAG_SRC/0x11-t10.md"},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:accepted-methodology"])
        self.assertEqual(result.rejected_refs, ["rag:legacy-rag-src"])
        self.assertTrue(any("source Markdown" in error for error in result.errors))

    def _rag(
        self,
        ref: str,
        *,
        source_type: str,
        metadata: dict[str, object] | None = None,
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind="rag",
            authority="advisory",
            source_type=source_type,
            purpose="methodology_hint",
            sink="rag_index",
            content="Advisory material must not come from legacy source Markdown drops.",
            citations=[ref],
            metadata={} if metadata is None else metadata,
        )


if __name__ == "__main__":
    unittest.main()
