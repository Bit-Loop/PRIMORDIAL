from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextFindingSinkTests(unittest.TestCase):
    def test_finding_sink_rejects_collaboration_advisory_and_generated_sources(self) -> None:
        envelopes = [
            self._finding("finding:runtime", "runtime_state"),
            self._finding("finding:github", "github"),
            self._finding("finding:notion", "notion"),
            self._finding("finding:ctfd", "ctfd"),
            self._finding("finding:writeup", "writeup"),
            self._finding("finding:generated-export", "generated_export"),
            self._finding("finding:ai-output", "ai_output"),
        ]

        result = ContextSinkValidator().validate("finding", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["finding:runtime"])
        self.assertEqual(
            result.rejected_refs,
            [
                "finding:ai-output",
                "finding:ctfd",
                "finding:generated-export",
                "finding:github",
                "finding:notion",
                "finding:writeup",
            ],
        )
        for source_type in ("ai_output", "ctfd", "generated_export", "github", "notion", "writeup"):
            with self.subTest(source_type=source_type):
                self.assertTrue(any(f"source_type={source_type}" in error for error in result.errors))

    def test_finding_sink_rejects_unresolved_evidence_support_when_known_refs_are_supplied(self) -> None:
        envelopes = [
            self._finding(
                "finding:observed-service",
                "runtime_state",
                citations=["evidence:observed-service"],
            ),
            self._finding(
                "finding:fabricated-support",
                "runtime_state",
                citations=["evidence:made-up"],
            ),
        ]

        result = ContextSinkValidator().validate(
            "finding",
            envelopes,
            known_evidence_refs={"evidence:observed-service"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["finding:observed-service"])
        self.assertEqual(result.rejected_refs, ["finding:fabricated-support"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_finding_sink_rejects_finding_shaped_records_without_finding_refs(self) -> None:
        envelopes = [
            self._finding("finding:observed-service", "runtime_state"),
            self._finding("model:finding-shaped", "runtime_state"),
        ]

        result = ContextSinkValidator().validate("finding", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["finding:observed-service"])
        self.assertEqual(result.rejected_refs, ["model:finding-shaped"])
        self.assertTrue(any("finding:<id>" in error for error in result.errors))

    def test_finding_sink_rejects_mixed_non_evidence_citation_support(self) -> None:
        envelopes = [
            self._finding("finding:evidence-only", "runtime_state", citations=["evidence:observed-service"]),
            self._finding(
                "finding:rag-mixed",
                "runtime_state",
                citations=["evidence:observed-service", "rag:methodology"],
            ),
            self._finding(
                "finding:model-mixed",
                "runtime_state",
                citations=["evidence:observed-service", "model:summary"],
            ),
            self._finding(
                "finding:github-mixed",
                "runtime_state",
                citations=["evidence:observed-service", "github:issue-1"],
            ),
            self._finding(
                "finding:notion-mixed",
                "runtime_state",
                citations=["evidence:observed-service", "notion:note-1"],
            ),
            self._finding(
                "finding:ctfd-mixed",
                "runtime_state",
                citations=["evidence:observed-service", "ctfd:challenge-1"],
            ),
            self._finding(
                "finding:chat-mixed",
                "runtime_state",
                citations=["evidence:observed-service", "chat:operator-context"],
            ),
        ]

        result = ContextSinkValidator().validate("finding", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["finding:evidence-only"])
        self.assertEqual(
            result.rejected_refs,
            [
                "finding:chat-mixed",
                "finding:ctfd-mixed",
                "finding:github-mixed",
                "finding:model-mixed",
                "finding:notion-mixed",
                "finding:rag-mixed",
            ],
        )
        self.assertTrue(any("non-evidence citation support" in error for error in result.errors))

    def test_finding_sink_rejects_confirmed_finding_without_evidence_support(self) -> None:
        envelope = self._finding(
            "finding:confirmed-rag-only",
            "runtime_state",
            authority="confirmed",
            citations=["rag:version-hint"],
        )

        result = ContextSinkValidator().validate("finding", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["finding:confirmed-rag-only"])
        self.assertTrue(any("requires evidence:<id>" in error for error in result.errors))

    def _finding(
        self,
        ref: str,
        source_type: str,
        *,
        authority: str = "reviewed",
        citations: list[str] | None = None,
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind="finding",
            authority=authority,
            source_type=source_type,
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="finding_generation",
            sink="finding",
            content="Reviewed findings must be promoted from controlled runtime records.",
            citations=citations or ["evidence:observed-service"],
        )


if __name__ == "__main__":
    unittest.main()
