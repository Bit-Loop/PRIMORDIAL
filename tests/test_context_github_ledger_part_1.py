from __future__ import annotations

from tests.test_context_github_ledger_common import *


class GitHubLedgerSinkTestsPart1(GitHubLedgerSinkTestsBase):
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

    def test_github_ledger_rejects_nested_truth_like_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-confirmed-authority",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_ledger",
            content="Nested GitHub authority must not turn engineering context into target truth.",
            citations=["github:nested-confirmed-authority"],
            metadata={
                "context_type": "engineering_context",
                "metadata": {"authority": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-confirmed-authority"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_github_ledger_rejects_plural_nested_truth_like_authorities(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-confirmed-authorities",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_ledger",
            content="Nested plural GitHub authorities must not turn engineering context into target truth.",
            citations=["github:nested-confirmed-authorities"],
            metadata={
                "context_type": "engineering_context",
                "metadata": {"authorities": ["confirmed"]},
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-confirmed-authorities"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_github_ledger_rejects_plural_nested_unsupported_source_types(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-model-source-type",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_ledger",
            content="Nested source metadata must not turn model output into GitHub ledger context.",
            citations=["github:nested-model-source-type"],
            metadata={
                "context_type": "engineering_context",
                "metadata": {"source_types": ["ai_output"]},
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-model-source-type"])
        self.assertTrue(any("unsupported source_type=ai_output" in error for error in result.errors))

    def test_github_ledger_rejects_target_truth_and_authority_mutations(self) -> None:
        result = ContextSinkValidator().validate("github_ledger", self._github_truth_mutation_envelopes())

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

    def _github_truth_mutation_envelopes(self) -> list[ContextEnvelope]:
        return [
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

__all__ = ["GitHubLedgerSinkTestsPart1"]
