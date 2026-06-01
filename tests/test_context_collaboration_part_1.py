from __future__ import annotations

from tests.test_context_collaboration_common import *


class ContextCollaborationSinkTestsPart1(ContextCollaborationSinkTestsBase):
    def test_discord_notification_rejects_non_authority_sources_with_authority_labels(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="chat:approval-notice",
                kind="approval",
                authority="authoritative",
                source_type="chat",
                target_id="target-a",
                purpose="discord_notification",
                sink="discord_notification",
                content="Chat text must not become an approval-shaped operator notification.",
                citations=["chat:approval-notice"],
                metadata={"labels": ["advisory"]},
            ),
            ContextEnvelope(
                ref="model:observed-notice",
                kind="model_summary",
                authority="observed",
                source_type="ai_output",
                target_id="target-a",
                purpose="discord_notification",
                sink="discord_notification",
                content="Model output must not become an observed target fact in notifications.",
                citations=["model:observed-notice"],
                metadata={"labels": ["advisory"]},
            ),
        ]

        result = ContextSinkValidator().validate("discord_notification", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["chat:approval-notice", "model:observed-notice"])
        self.assertTrue(any("non-authority source" in error for error in result.errors))

    def test_discord_notification_rejects_truth_like_authority_on_model_summary(self) -> None:
        envelope = ContextEnvelope(
            ref="model:confirmed-runtime-notice",
            kind="model_summary",
            authority="confirmed",
            source_type="runtime_state",
            target_id="target-a",
            purpose="discord_notification",
            sink="discord_notification",
            content="Runtime-stored model summaries must not notify as confirmed target truth.",
            citations=["evidence:http-banner"],
            metadata={"labels": ["advisory"]},
        )

        result = ContextSinkValidator().validate("discord_notification", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["model:confirmed-runtime-notice"])
        self.assertTrue(any("truth-like authority" in error for error in result.errors))

    def test_discord_notification_rejects_uncited_rag_context_even_when_labeled(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:uncited-cve-notice",
            kind="rag",
            authority="advisory",
            source_type="vuln_intel",
            target_id="target-a",
            purpose="discord_notification",
            sink="discord_notification",
            content="Potential vulnerability intelligence should remain cited advisory context.",
            citations=[],
            metadata={"labels": ["advisory"]},
        )

        result = ContextSinkValidator().validate("discord_notification", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:uncited-cve-notice"])
        self.assertTrue(any("must cite its own rag ref" in error for error in result.errors))

    def test_discord_notification_rejects_source_markdown_path(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:source-markdown-notice",
            kind="rag",
            authority="advisory",
            source_type="vuln_intel",
            target_id="target-a",
            purpose="discord_notification",
            sink="discord_notification",
            content="Quarantined Markdown must not become Discord advisory context.",
            citations=["rag:source-markdown-notice"],
            metadata={
                "labels": ["advisory"],
                "source_file": "runtime/quarantine/markdown/docs/RAG_SRC/0x11-t10.md",
            },
        )

        result = ContextSinkValidator().validate(
            "discord_notification",
            [envelope],
            known_rag_refs={"rag:source-markdown-notice"},
        )

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:source-markdown-notice"])
        self.assertTrue(any("source_markdown" in error for error in result.errors))

    def test_discord_notification_quarantines_unlabeled_external_collaboration_refs(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="github:issue-notice",
                kind="github_ref",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                purpose="discord_notification",
                sink="discord_notification",
                content="A GitHub issue reports an engineering note.",
                citations=["github:issue-notice"],
            ),
            ContextEnvelope(
                ref="notion:operator-note",
                kind="notion_ref",
                authority="asserted",
                source_type="notion",
                target_id="target-a",
                purpose="discord_notification",
                sink="discord_notification",
                content="A Notion note mentions a possible next step.",
                citations=["notion:operator-note"],
            ),
            ContextEnvelope(
                ref="ctfd:challenge-notice",
                kind="ctfd_ref",
                authority="asserted",
                source_type="ctfd",
                target_id="target-a",
                purpose="discord_notification",
                sink="discord_notification",
                content="CTFd challenge metadata lists a target URL.",
                citations=["ctfd:challenge-notice"],
            ),
        ]

        result = ContextSinkValidator().validate("discord_notification", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.quarantined_refs,
            ["ctfd:challenge-notice", "github:issue-notice", "notion:operator-note"],
        )
        self.assertTrue(any("requires external collaboration label" in error for error in result.errors))

    def test_github_issue_sink_rejects_human_readable_unredacted_evidence_refs(self) -> None:
        envelope = ContextEnvelope(
            ref="github:display-evidence-leak",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_issue",
            content="Engineering issue text must not carry unredacted target evidence refs.",
            citations=["github:display-evidence-leak"],
            metadata={
                "Context type": "failure analysis",
                "Evidence refs": ["evidence:raw-request-response"],
                "Redacted": "no",
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:display-evidence-leak"])
        self.assertTrue(any("requires redacted evidence refs" in error for error in result.errors))

    def test_github_issue_sink_rejects_confirmed_authority_label(self) -> None:
        envelope = ContextEnvelope(
            ref="github:confirmed-issue-projection",
            kind="github_ref",
            authority="confirmed",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_issue",
            content="GitHub issue projections must not carry confirmed target-truth authority.",
            citations=["github:confirmed-issue-projection"],
            metadata={"Context type": "failure analysis"},
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:confirmed-issue-projection"])
        self.assertTrue(any("target authority" in error for error in result.errors))

    def test_github_issue_sink_rejects_target_fact_markers(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="github:target-fact-issue",
                kind="github_ref",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_issue",
                content="GitHub issue prose claims target-a has tcp/80 open.",
                citations=["github:target-fact-issue"],
                metadata={
                    "context_type": "engineering_context",
                    "contains_target_fact": True,
                },
            ),
            ContextEnvelope(
                ref="github:target-factual-claim-issue",
                kind="engineering_context",
                authority="asserted",
                source_type="github_project_context",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_issue",
                content="A regression note repeats target-state prose.",
                citations=["github:target-factual-claim-issue"],
                metadata={
                    "context_type": "regression_failure",
                    "target factual claim": "yes",
                },
            ),
            ContextEnvelope(
                ref="github:ordinary-parser-issue",
                kind="github_ref",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                purpose="patch_planning",
                sink="github_issue",
                content="Parser failure issue without target truth.",
                citations=["github:ordinary-parser-issue"],
                metadata={"context_type": "parser_failure"},
            ),
        ]

        result = ContextSinkValidator().validate("github_issue", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["github:ordinary-parser-issue"])
        self.assertEqual(
            result.rejected_refs,
            ["github:target-fact-issue", "github:target-factual-claim-issue"],
        )
        self.assertTrue(any("target fact" in error for error in result.errors))

    def test_github_issue_sink_rejects_candidate_task_records(self) -> None:
        envelope = ContextEnvelope(
            ref="github:issue-candidate-action",
            kind="candidate_task",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_issue",
            content="GitHub issue prose must not become an operational target task.",
            citations=["github:issue-candidate-action"],
            metadata={"context_type": "engineering_context"},
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:issue-candidate-action"])
        self.assertTrue(any("unsupported engineering issue kind" in error for error in result.errors))

    def test_github_issue_sink_rejects_source_markdown_path(self) -> None:
        envelope = ContextEnvelope(
            ref="github:source-markdown-issue",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            target_id="target-a",
            purpose="patch_planning",
            sink="github_issue",
            content="Quarantined Markdown must not become GitHub issue material.",
            citations=["github:source-markdown-issue"],
            metadata={
                "context_type": "engineering_context",
                "source_file": "runtime/quarantine/markdown/docs/RAG_SRC/0x11-t10.md",
            },
        )

        result = ContextSinkValidator().validate("github_issue", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:source-markdown-issue"])
        self.assertTrue(any("source_markdown" in error for error in result.errors))

__all__ = ["ContextCollaborationSinkTestsPart1"]
