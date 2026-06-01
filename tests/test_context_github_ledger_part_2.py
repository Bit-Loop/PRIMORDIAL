from __future__ import annotations

from tests.test_context_github_ledger_common import *


class GitHubLedgerSinkTestsPart2(GitHubLedgerSinkTestsBase):
    def test_github_ledger_rejects_engineering_context_that_marks_finding_confirmed(self) -> None:
        envelope = ContextEnvelope(
            ref="github:display-confirmed-finding",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_ledger",
            content="A GitHub issue must not confirm a target finding through metadata.",
            citations=["github:display-confirmed-finding"],
            metadata={
                "Context Type": "Engineering Context",
                "Finding status": "Confirmed",
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:display-confirmed-finding"])
        self.assertTrue(any("confirmed finding" in error for error in result.errors))

    def test_github_ledger_rejects_target_fact_markers_on_engineering_context(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="github:target-fact-marker",
                kind="github_ref",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_ledger",
                content="A GitHub issue says target-a has tcp/80 open.",
                citations=["github:target-fact-marker"],
                metadata={
                    "context_type": "engineering_context",
                    "contains_target_fact": True,
                },
            ),
            ContextEnvelope(
                ref="github:target-factual-claim-marker",
                kind="engineering_context",
                authority="asserted",
                source_type="github_project_context",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_ledger",
                content="A GitHub regression note repeats a target-state claim.",
                citations=["github:target-factual-claim-marker"],
                metadata={
                    "context_type": "regression_failure",
                    "target factual claim": "yes",
                },
            ),
            ContextEnvelope(
                ref="github:ordinary-parser-context",
                kind="github_ref",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_ledger",
                content="A parser regression note without target truth.",
                citations=["github:ordinary-parser-context"],
                metadata={"context_type": "parser_failure"},
            ),
        ]

        result = ContextSinkValidator().validate("github_ledger", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["github:ordinary-parser-context"])
        self.assertEqual(
            result.rejected_refs,
            ["github:target-fact-marker", "github:target-factual-claim-marker"],
        )
        self.assertTrue(any("target fact" in error for error in result.errors))

    def test_github_ledger_accepts_human_readable_redacted_sensitive_context(self) -> None:
        envelope = ContextEnvelope(
            ref="github:redacted-secret-note",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_ledger",
            content="Redacted engineering note references sensitive target material without exposing it.",
            citations=["github:redacted-secret-note"],
            metadata={
                "context_type": "failure_analysis",
                "Contains secret": "yes",
                "Redacted": "yes",
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertTrue(result.valid)
        self.assertEqual(result.accepted_refs, ["github:redacted-secret-note"])
        self.assertEqual(result.rejected_refs, [])
        self.assertEqual(result.errors, [])

    def test_github_ledger_requires_redaction_for_evidence_refs(self) -> None:
        unredacted = ContextEnvelope(
            ref="github:raw-evidence-link",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_ledger",
            content="Engineering ledger entry links target evidence without redaction.",
            citations=["evidence:raw-request-response"],
            metadata={
                "context_type": "failure_analysis",
                "evidence_refs": ["evidence:raw-request-response"],
            },
        )
        redacted = ContextEnvelope(
            ref="github:redacted-evidence-link",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_ledger",
            content="Engineering ledger entry links only redacted evidence refs.",
            citations=["evidence:redacted-request-response"],
            metadata={
                "context_type": "failure_analysis",
                "evidence_refs": ["evidence:redacted-request-response"],
                "evidence_refs_redacted": True,
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [unredacted, redacted])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["github:redacted-evidence-link"])
        self.assertEqual(result.rejected_refs, ["github:raw-evidence-link"])
        self.assertTrue(any("evidence refs require redaction" in error for error in result.errors))

__all__ = ["GitHubLedgerSinkTestsPart2"]
