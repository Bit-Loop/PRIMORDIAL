from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextRagIndexWriteupPolicyTests(unittest.TestCase):
    def test_rag_index_rejects_writeups_when_writeup_access_policy_is_closed_book(self) -> None:
        envelopes = [
            self._rag("rag:allowed-methodology", source_type="methodology_doc"),
            self._rag(
                "rag:closed-book-writeup",
                source_type="writeup",
                metadata={"writeup_access_policy": "closed_book"},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:allowed-methodology"])
        self.assertEqual(result.rejected_refs, ["rag:closed-book-writeup"])
        self.assertTrue(any("rejects writeup" in error for error in result.errors))

    def test_rag_index_rejects_postmortem_only_writeups_outside_postmortem_mode(self) -> None:
        envelopes = [
            self._rag(
                "rag:active-postmortem-only-writeup",
                source_type="writeup",
                metadata={"writeup_access_policy": "postmortem_only"},
            ),
            self._rag(
                "rag:postmortem-writeup",
                source_type="writeup",
                metadata={"mode": "postmortem", "writeup_access_policy": "postmortem_only"},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:postmortem-writeup"])
        self.assertEqual(result.rejected_refs, ["rag:active-postmortem-only-writeup"])
        self.assertTrue(any("postmortem_only" in error for error in result.errors))

    def test_rag_index_rejects_nested_writeup_source_types_in_closed_book_mode(self) -> None:
        envelope = self._rag(
            "rag:nested-closed-book-writeup",
            source_type="methodology_doc",
            metadata={
                "metadata": {
                    "benchmark_mode": "closed_book",
                    "source_types": ["writeup"],
                },
            },
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:nested-closed-book-writeup"])
        self.assertTrue(any("rejects writeup" in error and "closed_book" in error for error in result.errors))

    def test_rag_index_rejects_list_valued_writeup_policy_metadata(self) -> None:
        envelopes = [
            self._rag(
                "rag:list-closed-book-writeup",
                source_type="writeup",
                metadata={"benchmark_mode": ["open_book", "closed_book"]},
            ),
            self._rag(
                "rag:list-postmortem-only-writeup",
                source_type="writeup",
                metadata={"writeup_access_policy": ["allowed", "postmortem_only"]},
            ),
            self._rag(
                "rag:list-writeups-disabled",
                source_type="writeup",
                metadata={"writeups_allowed": [True, False]},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            [
                "rag:list-closed-book-writeup",
                "rag:list-postmortem-only-writeup",
                "rag:list-writeups-disabled",
            ],
        )
        self.assertTrue(any("closed_book" in error for error in result.errors))
        self.assertTrue(any("postmortem_only" in error for error in result.errors))
        self.assertTrue(any("writeups_allowed" in error or "unspecified" in error for error in result.errors))

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
            content="Methodology corpus content must remain advisory when indexed for retrieval.",
            citations=[ref],
            metadata={} if metadata is None else metadata,
        )


if __name__ == "__main__":
    unittest.main()
