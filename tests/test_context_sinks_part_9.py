from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart9(ContextSinkValidatorTestsBase):
    def test_github_issue_rejects_nested_truth_like_authority(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-confirmed-issue-projection",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested GitHub issue metadata must not project confirmed target-truth authority.",
            citations=["github:nested-confirmed-issue-projection"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"authority": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-confirmed-issue-projection"])
        self.assertTrue(any("target authority" in error for error in result.errors))

    def test_github_issue_rejects_nested_unredacted_evidence_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-evidence-leak",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested evidence refs must still require redaction before GitHub projection.",
            citations=["github:nested-evidence-leak"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"evidence_refs": ["evidence:raw-request-response"]},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-evidence-leak"])
        self.assertTrue(any("requires redacted evidence refs" in error for error in result.errors))

    def test_github_issue_rejects_nested_unredacted_evidence_ids(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-evidence-id-leak",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested evidence ids must still require redaction before GitHub projection.",
            citations=["github:nested-evidence-id-leak"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"evidence_ids": ["evidence:raw-request-response"]},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-evidence-id-leak"])
        self.assertTrue(any("requires redacted evidence refs" in error for error in result.errors))

    def test_github_issue_rejects_nested_unsupported_context_type(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-operator-intent-context",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested context type must not turn GitHub issue projection into authority context.",
            citations=["github:nested-operator-intent-context"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"context_type": "operator_intent"},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-operator-intent-context"])
        self.assertTrue(any("unsupported engineering issue context_type=operator_intent" in error for error in result.errors))

    def test_github_issue_rejects_plural_nested_unsupported_context_types(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-operator-intent-context-types",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested plural context types must not turn GitHub issue projection into authority context.",
            citations=["github:nested-operator-intent-context-types"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"context_types": ["operator_intent"]},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-operator-intent-context-types"])
        self.assertTrue(any("unsupported engineering issue context_type=operator_intent" in error for error in result.errors))

    def test_github_issue_rejects_nested_unsupported_source_type(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-ai-output-source",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested source type must not disguise raw model output as GitHub issue material.",
            citations=["github:nested-ai-output-source"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"source_type": "ai_output"},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-ai-output-source"])
        self.assertTrue(any("unsupported engineering issue source_type=ai_output" in error for error in result.errors))

    def test_github_issue_rejects_nested_evidence_kind(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-evidence-kind",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested kind must not turn GitHub issue projection into evidence.",
            citations=["github:nested-evidence-kind"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"kind": "evidence"},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-evidence-kind"])
        self.assertTrue(any("target authority" in error for error in result.errors))

    def test_github_issue_rejects_plural_nested_evidence_kinds(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-evidence-kinds",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="patch_planning",
            sink="github_issue",
            content="Nested plural kinds must not turn GitHub issue projection into evidence.",
            citations=["github:nested-evidence-kinds"],
            metadata={
                "context_type": "failure_analysis",
                "metadata": {"kinds": ["evidence"]},
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-evidence-kinds"])
        self.assertTrue(any("target authority" in error for error in result.errors))

    def test_github_ledger_rejects_context_restrictions_that_exclude_ledger(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="github:prompt-only-ledger",
                kind="github_ref",
                authority="advisory",
                source_type="github",
                purpose="github_ledger",
                sink="github_ledger",
                content="Prompt-only GitHub context must not enter the durable GitHub ledger sink.",
                citations=[],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"], "context_type": "engineering_context"},
            ),
            ContextEnvelope(
                ref="github:ledger-denied",
                kind="github_ref",
                authority="advisory",
                source_type="github",
                purpose="github_ledger",
                sink="github_ledger",
                content="GitHub-ledger-denied context must not enter the durable GitHub ledger sink.",
                citations=[],
                invalid_for=["github_ledger"],
                metadata={"invalid_for": ["github_ledger"], "context_type": "engineering_context"},
            ),
        ]

        result = ContextSinkValidator().validate("github_ledger", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:ledger-denied", "github:prompt-only-ledger"])
        self.assertTrue(any("valid_for excludes github_ledger" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes github_ledger" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart9"]
