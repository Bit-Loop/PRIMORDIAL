from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextRagIndexTests(unittest.TestCase):
    def test_rag_index_rejects_non_advisory_authority_labels(self) -> None:
        envelopes = [
            self._rag("rag:methodology", "advisory"),
            self._rag("rag:unverified-methodology", "unverified"),
            self._rag("rag:historical-methodology", "historical"),
            self._rag("rag:authoritative-methodology", "authoritative"),
            self._rag("rag:observed-methodology", "observed"),
            self._rag("rag:asserted-methodology", "asserted"),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(
            result.accepted_refs,
            ["rag:historical-methodology", "rag:methodology", "rag:unverified-methodology"],
        )
        self.assertEqual(
            result.rejected_refs,
            ["rag:asserted-methodology", "rag:authoritative-methodology", "rag:observed-methodology"],
        )
        self.assertTrue(any("requires advisory authority" in error for error in result.errors))

    def test_rag_index_rejects_non_advisory_source_types(self) -> None:
        envelopes = [
            self._rag("rag:methodology", "advisory", source_type="methodology_doc"),
            self._rag("rag:vuln-intel", "advisory", source_type="vuln_intel"),
            self._rag("rag:validated-doc", "advisory", source_type="validated_external"),
            self._rag("rag:ctf-manifest-hint", "advisory", source_type="ctf_manifest"),
            self._rag("rag:postmortem-writeup", "advisory", source_type="writeup"),
            self._rag("rag:runtime-state", "advisory", source_type="runtime_state"),
            self._rag("rag:tool-output", "advisory", source_type="tool_output"),
            self._rag("rag:manual-artifact", "advisory", source_type="manual_artifact"),
            self._rag("rag:notion-projection", "advisory", source_type="notion"),
            self._rag("rag:github-projection", "advisory", source_type="github"),
            self._rag("rag:ctfd-projection", "advisory", source_type="ctfd"),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(
            result.accepted_refs,
            [
                "rag:ctf-manifest-hint",
                "rag:methodology",
                "rag:postmortem-writeup",
                "rag:validated-doc",
                "rag:vuln-intel",
            ],
        )
        self.assertEqual(
            result.rejected_refs,
            [
                "rag:ctfd-projection",
                "rag:github-projection",
                "rag:manual-artifact",
                "rag:notion-projection",
                "rag:runtime-state",
                "rag:tool-output",
            ],
        )
        self.assertTrue(any("requires advisory source_type" in error for error in result.errors))

    def test_rag_index_rejects_unknown_advisory_kind(self) -> None:
        envelopes = [
            self._rag("rag:methodology", "advisory", source_type="methodology_doc"),
            ContextEnvelope(
                ref="rag:unknown-advisory-kind",
                kind="external_reference",
                authority="advisory",
                source_type="methodology_doc",
                purpose="methodology_hint",
                sink="rag_index",
                content="Unknown advisory kinds must not enter the active RAG index.",
                citations=["rag:unknown-advisory-kind"],
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:methodology"])
        self.assertEqual(result.rejected_refs, ["rag:unknown-advisory-kind"])
        self.assertTrue(any("requires kind=rag" in error for error in result.errors))

    def test_rag_index_rejects_fabricated_unknown_rag_ref(self) -> None:
        envelopes = [
            self._rag("rag:methodology", "advisory", source_type="methodology_doc"),
            ContextEnvelope.from_rag_chunk(
                {
                    "text": "A RAG chunk without an indexed identity must not enter active retrieval.",
                    "metadata": {"source_type": "methodology_doc"},
                },
                purpose="methodology_hint",
                sink="rag_index",
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:methodology"])
        self.assertEqual(result.rejected_refs, ["rag:unknown"])
        self.assertTrue(any("requires explicit rag ref" in error for error in result.errors))

    def test_rag_index_requires_rag_records_to_cite_their_own_ref(self) -> None:
        envelopes = [
            self._rag("rag:self-cited", "advisory", source_type="methodology_doc"),
            self._rag(
                "rag:missing-self-citation",
                "advisory",
                source_type="methodology_doc",
                citations=[],
            ),
            self._rag(
                "rag:note-cited",
                "advisory",
                source_type="methodology_doc",
                citations=["note:operator"],
            ),
            self._rag(
                "rag:wrong-rag-cited",
                "advisory",
                source_type="methodology_doc",
                citations=["rag:other"],
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:self-cited"])
        self.assertEqual(
            result.rejected_refs,
            ["rag:missing-self-citation", "rag:note-cited", "rag:wrong-rag-cited"],
        )
        self.assertTrue(any("must cite its own rag ref" in error for error in result.errors))

    def test_rag_index_rejects_unresolved_rag_citation_support(self) -> None:
        envelope = self._rag(
            "rag:indexed-method",
            "advisory",
            source_type="methodology_doc",
            citations=["rag:indexed-method", "rag:made-up"],
        )

        result = ContextSinkValidator().validate(
            "rag_index",
            [envelope],
            known_rag_refs={"rag:indexed-method"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:indexed-method"])
        self.assertTrue(any("unresolved rag citation" in error for error in result.errors))
        self.assertTrue(any("rag:made-up" in error for error in result.errors))

    def test_rag_index_rejects_numeric_falsy_ingest_and_retrieval_flags(self) -> None:
        envelopes = [
            self._rag("rag:ingest-zero", "advisory", metadata={"ingest_allowed": 0}),
            self._rag(
                "rag:retrieval-zero",
                "advisory",
                metadata={"operational_retrieval_allowed": 0},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:ingest-zero", "rag:retrieval-zero"])
        self.assertTrue(any("ingest_allowed=false" in error for error in result.errors))
        self.assertTrue(any("operational_retrieval_allowed=false" in error for error in result.errors))

    def test_rag_index_rejects_target_fact_markers(self) -> None:
        envelopes = [
            self._rag("rag:ordinary-methodology", "advisory"),
            self._rag(
                "rag:target-fact-advisory",
                "advisory",
                source_type="vuln_intel",
                citations=["rag:target-fact-advisory", "evidence:observed-service"],
                metadata={"advisory_claim": True, "contains_target_fact": True},
            ),
            self._rag(
                "rag:target-factual-claim",
                "advisory",
                source_type="methodology_doc",
                citations=["rag:target-factual-claim", "evidence:observed-service"],
                metadata={"advisory_claim": "yes", "target factual claim": "yes"},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:ordinary-methodology"])
        self.assertEqual(
            result.rejected_refs,
            ["rag:target-fact-advisory", "rag:target-factual-claim"],
        )
        self.assertTrue(any("target fact" in error for error in result.errors))

    def _rag(
        self,
        ref: str,
        authority: str,
        *,
        source_type: str = "methodology_doc",
        citations: list[str] | None = None,
        metadata: dict[str, object] | None = None,
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind="rag",
            authority=authority,
            source_type=source_type,
            purpose="methodology_hint",
            sink="rag_index",
            content="Methodology corpus content must remain advisory when indexed for retrieval.",
            citations=[ref] if citations is None else citations,
            metadata={} if metadata is None else metadata,
        )


if __name__ == "__main__":
    unittest.main()
