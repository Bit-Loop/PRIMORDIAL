from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart10(ContextSinkValidatorTestsBase):
    def test_github_ledger_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="github:export-url-ledger",
            kind="github_ref",
            authority="advisory",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="github_ledger",
            sink="github_ledger",
            content="Generated export URLs must not enter the durable GitHub ledger.",
            citations=[],
            metadata={
                "context_type": "engineering_context",
                "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:export-url-ledger"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_github_ledger_rejects_nested_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-export-url-ledger",
            kind="github_ref",
            authority="advisory",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="github_ledger",
            sink="github_ledger",
            content="Nested generated export URLs must not enter the durable GitHub ledger.",
            citations=[],
            metadata={
                "context_type": "engineering_context",
                "metadata": {
                    "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
                },
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-export-url-ledger"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_github_ledger_rejects_nested_sensitive_metadata_without_redaction(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-sensitive-ledger",
            kind="github_ref",
            authority="advisory",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="github_ledger",
            sink="github_ledger",
            content="Nested sensitive flags must not enter the durable GitHub ledger unredacted.",
            citations=[],
            metadata={
                "context_type": "engineering_context",
                "metadata": {"contains_secret": True},
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-sensitive-ledger"])
        self.assertTrue(any("sensitive target material requires redaction" in error for error in result.errors))

    def test_github_ledger_rejects_nested_evidence_refs_without_redaction(self) -> None:
        envelope = ContextEnvelope(
            ref="github:nested-evidence-refs-ledger",
            kind="github_ref",
            authority="advisory",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="github_ledger",
            sink="github_ledger",
            content="Nested evidence refs must not enter the durable GitHub ledger unredacted.",
            citations=[],
            metadata={
                "context_type": "engineering_context",
                "metadata": {"evidence_refs": ["evidence:http-banner"]},
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:nested-evidence-refs-ledger"])
        self.assertTrue(any("evidence refs require redaction" in error for error in result.errors))

    def test_github_ledger_rejects_masked_nested_evidence_refs_without_redaction(self) -> None:
        envelope = ContextEnvelope(
            ref="github:masked-nested-evidence-refs-ledger",
            kind="github_ref",
            authority="advisory",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="github_ledger",
            sink="github_ledger",
            content="Top-level empty evidence refs must not mask nested evidence refs.",
            citations=[],
            metadata={
                "context_type": "engineering_context",
                "evidence_refs": [],
                "metadata": {"evidence_refs": ["evidence:http-banner"]},
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:masked-nested-evidence-refs-ledger"])
        self.assertTrue(any("evidence refs require redaction" in error for error in result.errors))

    def test_github_ledger_rejects_masked_nested_confirmed_finding_status(self) -> None:
        envelope = ContextEnvelope(
            ref="github:masked-nested-confirmed-finding",
            kind="github_ref",
            authority="advisory",
            source_type="github",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="github_ledger",
            sink="github_ledger",
            content="Top-level draft status must not mask nested confirmed finding status.",
            citations=[],
            metadata={
                "context_type": "engineering_context",
                "finding_status": "draft",
                "metadata": {"finding_status": "confirmed"},
            },
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:masked-nested-confirmed-finding"])
        self.assertTrue(any("confirmed finding" in error for error in result.errors))

    def test_ctfd_registry_rejects_context_restrictions_that_exclude_registry(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="ctfd:prompt-only-challenge",
                kind="challenge_metadata",
                authority="advisory",
                source_type="ctfd",
                purpose="ctfd_registry",
                sink="ctfd_registry",
                content="Prompt-only challenge metadata must not enter the durable CTFd registry sink.",
                citations=["ctfd:challenge-1"],
                valid_for=["prompt"],
                metadata={"valid_for": ["prompt"], "record_type": "challenge_metadata"},
            ),
            ContextEnvelope(
                ref="ctfd:registry-denied-challenge",
                kind="challenge_metadata",
                authority="advisory",
                source_type="ctfd",
                purpose="ctfd_registry",
                sink="ctfd_registry",
                content="CTFd-registry-denied metadata must not enter the durable CTFd registry sink.",
                citations=["ctfd:challenge-2"],
                invalid_for=["ctfd_registry"],
                metadata={"invalid_for": ["ctfd_registry"], "record_type": "challenge_metadata"},
            ),
        ]

        result = ContextSinkValidator().validate("ctfd_registry", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:prompt-only-challenge", "ctfd:registry-denied-challenge"])
        self.assertTrue(any("valid_for excludes ctfd_registry" in error for error in result.errors))
        self.assertTrue(any("invalid_for excludes ctfd_registry" in error for error in result.errors))

    def test_ctfd_registry_rejects_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-export-url",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Generated export URLs must not enter the durable CTFd registry.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-export-url"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_ctfd_registry_rejects_nested_generated_export_source_url(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:registry-nested-export-url",
            kind="challenge_metadata",
            authority="advisory",
            source_type="ctfd",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="ctfd_registry",
            sink="ctfd_registry",
            content="Nested generated export URLs must not enter the durable CTFd registry.",
            citations=["ctfd:challenge-1"],
            metadata={
                "record_type": "challenge_metadata",
                "metadata": {
                    "source_url": "https://example.invalid/findings/notion/target-a/notion-export.md",
                },
            },
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:registry-nested-export-url"])
        self.assertTrue(any("generated export" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart10"]
