from __future__ import annotations

from tests.test_context_collaboration_common import *


class ContextCollaborationSinkTestsPart2(ContextCollaborationSinkTestsBase):
    def test_github_issue_sink_rejects_raw_chat_or_ai_sources(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="github:chat-wrapped-issue",
                kind="github_ref",
                authority="asserted",
                source_type="chat",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_issue",
                content="Raw chat text must not become GitHub issue material.",
                citations=["github:chat-wrapped-issue"],
                metadata={"context_type": "engineering_context"},
            ),
            ContextEnvelope(
                ref="github:model-wrapped-issue",
                kind="github_ref",
                authority="asserted",
                source_type="ai_output",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_issue",
                content="Raw model output must not become GitHub issue material.",
                citations=["github:model-wrapped-issue"],
                metadata={"context_type": "engineering_context"},
            ),
        ]

        result = ContextSinkValidator().validate("github_issue", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:chat-wrapped-issue", "github:model-wrapped-issue"])
        self.assertTrue(any("unsupported engineering issue source_type" in error for error in result.errors))

    def test_github_issue_sink_rejects_scalar_unredacted_evidence_ref_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="github:scalar-evidence-leak",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_issue",
            content="Scalar evidence ref metadata must still require redaction before GitHub projection.",
            citations=["github:scalar-evidence-leak"],
            metadata={
                "Context type": "failure analysis",
                "Evidence refs": "evidence:raw-request-response",
                "Redacted": "no",
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:scalar-evidence-leak"])
        self.assertTrue(any("requires redacted evidence refs" in error for error in result.errors))

    def test_github_issue_sink_rejects_whitespace_padded_unredacted_evidence_ref_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="github:padded-evidence-leak",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_issue",
            content="Whitespace-padded evidence ref metadata must still require redaction.",
            citations=["github:padded-evidence-leak"],
            metadata={
                "Context type": "failure analysis",
                "Evidence refs": " evidence:raw-request-response ",
                "Redacted": "no",
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:padded-evidence-leak"])
        self.assertTrue(any("requires redacted evidence refs" in error for error in result.errors))

__all__ = ["ContextCollaborationSinkTestsPart2"]
