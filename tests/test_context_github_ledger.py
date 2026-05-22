from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class GitHubLedgerSinkTests(unittest.TestCase):
    def test_github_ledger_accepts_engineering_context_only(self) -> None:
        envelope = ContextEnvelope(
            ref="github:issue-parser-regression",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_ledger",
            content="Parser regression issue imported as engineering context.",
            citations=["github:issue-parser-regression"],
            metadata={
                "context_type": "engineering_context",
                "failure_analysis_id": "failure:parser-1",
                "test_ids": ["tests.test_context_github_ledger"],
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertTrue(result.valid)
        self.assertEqual(result.accepted_refs, ["github:issue-parser-regression"])
        self.assertEqual(result.rejected_refs, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])

    def test_github_ledger_rejects_truth_like_authority_on_engineering_context(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="github:authoritative-engineering-context",
                kind="github_ref",
                authority="authoritative",
                source_type="github",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_ledger",
                content="GitHub engineering context must not carry target-truth authority.",
                citations=["github:authoritative-engineering-context"],
                metadata={"context_type": "engineering_context"},
            ),
            ContextEnvelope(
                ref="github:observed-test-status",
                kind="test_status",
                authority="observed",
                source_type="github",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_ledger",
                content="GitHub test status may update engineering state, not target truth.",
                citations=["github:observed-test-status"],
                metadata={"context_type": "test_status"},
            ),
            ContextEnvelope(
                ref="github:confirmed-engineering-context",
                kind="github_ref",
                authority="confirmed",
                source_type="github",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_ledger",
                content="GitHub issue prose must not be accepted as confirmed target truth.",
                citations=["github:confirmed-engineering-context"],
                metadata={"context_type": "engineering_context"},
            ),
        ]

        result = ContextSinkValidator().validate("github_ledger", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            [
                "github:authoritative-engineering-context",
                "github:confirmed-engineering-context",
                "github:observed-test-status",
            ],
        )
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_github_ledger_rejects_target_truth_and_authority_mutations(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="github:evidence-claim",
                kind="evidence",
                authority="observed",
                source_type="github",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_ledger",
                content="A GitHub issue must not create target evidence.",
                citations=["github:evidence-claim"],
                metadata={"creates_evidence": True},
            ),
            ContextEnvelope(
                ref="github:approval-claim",
                kind="approval",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_ledger",
                content="A GitHub issue must not approve execution.",
                citations=["github:approval-claim"],
                metadata={"creates_approval": True},
            ),
            ContextEnvelope(
                ref="github:scope-change",
                kind="github_ref",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_ledger",
                content="A GitHub issue must not change scope.",
                citations=["github:scope-change"],
                metadata={"changes_scope": True},
            ),
            ContextEnvelope(
                ref="github:intent-change",
                kind="github_ref",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_ledger",
                content="A GitHub issue must not change Operator Intent.",
                citations=["github:intent-change"],
                metadata={"changes_operator_intent": True},
            ),
            ContextEnvelope(
                ref="github:action-authority",
                kind="github_ref",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_ledger",
                content="A GitHub issue must not authorize target action.",
                citations=["github:action-authority"],
                metadata={"authorizes_target_action": True},
            ),
            ContextEnvelope(
                ref="github:confirmed-finding",
                kind="finding",
                authority="reviewed",
                source_type="github",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_ledger",
                content="A GitHub issue must not confirm a finding.",
                citations=["github:confirmed-finding"],
                metadata={"confirms_finding": True},
            ),
        ]

        result = ContextSinkValidator().validate("github_ledger", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(
            result.rejected_refs,
            [
                "github:action-authority",
                "github:approval-claim",
                "github:confirmed-finding",
                "github:evidence-claim",
                "github:intent-change",
                "github:scope-change",
            ],
        )
        for phrase in ("evidence", "approval", "scope", "Operator Intent", "target action", "confirmed finding"):
            self.assertTrue(any(phrase in error for error in result.errors), phrase)

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


if __name__ == "__main__":
    unittest.main()
