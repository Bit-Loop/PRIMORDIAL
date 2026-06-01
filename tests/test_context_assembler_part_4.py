from __future__ import annotations

from tests.test_context_assembler_common import *


class ContextAssemblerTestsPart4(ContextAssemblerTestsBase):
    def test_context_assembler_policy_gate_rejects_advisory_candidate_task_sources(self) -> None:
        packet = ContextAssembler().assemble(
            self._policy_gate_candidate_source_envelopes(),
            purpose="policy_gate",
            role="policy_gate",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(
            [item["ref"] for item in packet["sections"]["MODEL_DERIVED"]],
            ["task:normalized-candidate"],
        )
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["task:writeup-candidate"], "role_forbidden")
        self.assertEqual(omitted_refs["task:vuln-intel-candidate"], "role_forbidden")
        self.assertEqual(omitted_refs["task:github-candidate"], "role_forbidden")
        self.assertEqual(omitted_refs["task:ctfd-candidate"], "role_forbidden")
        self.assertNotIn("writeup-derived action", packet["rendered"])
        self.assertNotIn("vulnerability-intel hint", packet["rendered"])
        self.assertNotIn("GitHub issue", packet["rendered"])
        self.assertNotIn("CTFd challenge", packet["rendered"])

    def _policy_gate_candidate_source_envelopes(self) -> list[ContextEnvelope]:
        return [
            ContextEnvelope(
                ref="task:normalized-candidate",
                kind="candidate_task",
                authority="asserted",
                source_type="runtime_state",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A normalized candidate action may be evaluated by the policy gate.",
                citations=[],
            ),
            ContextEnvelope(
                ref="task:writeup-candidate",
                kind="candidate_task",
                authority="advisory",
                source_type="writeup",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A writeup-derived action must not enter the policy gate prompt.",
                citations=["rag:writeup-step"],
            ),
            ContextEnvelope(
                ref="task:vuln-intel-candidate",
                kind="candidate_task",
                authority="advisory",
                source_type="vuln_intel",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A vulnerability-intel hint must not enter the policy gate prompt as a task.",
                citations=["rag:cve-hint"],
            ),
            ContextEnvelope(
                ref="task:github-candidate",
                kind="candidate_task",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A GitHub issue must not enter the policy gate prompt as a task.",
                citations=["github:issue-1"],
            ),
            ContextEnvelope(
                ref="task:ctfd-candidate",
                kind="candidate_task",
                authority="asserted",
                source_type="ctfd",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="CTFd challenge text must not enter the policy gate prompt as a task.",
                citations=["ctfd:challenge-1"],
            ),
        ]

    def test_context_assembler_policy_gate_rejects_truth_like_model_candidate_tasks(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="task:model-derived-candidate",
                kind="candidate_task",
                authority="derived",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A model-derived candidate action may be evaluated by the policy gate.",
                citations=[],
            ),
            ContextEnvelope(
                ref="task:model-observed-candidate",
                kind="candidate_task",
                authority="observed",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A model-derived candidate action must not claim observed authority.",
                citations=[],
            ),
            ContextEnvelope(
                ref="task:model-confirmed-candidate",
                kind="candidate_task",
                authority="confirmed",
                source_type="ai_output",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="policy_gate",
                sink="prompt",
                content="A model-derived candidate action must not claim confirmed authority.",
                citations=[],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="policy_gate",
            role="policy_gate",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(
            [item["ref"] for item in packet["sections"]["MODEL_DERIVED"]],
            ["task:model-derived-candidate"],
        )
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["task:model-observed-candidate"], "role_forbidden")
        self.assertEqual(omitted_refs["task:model-confirmed-candidate"], "role_forbidden")
        self.assertNotIn("claim observed authority", packet["rendered"])
        self.assertNotIn("claim confirmed authority", packet["rendered"])

    def test_context_assembler_omits_truth_like_github_and_notion_prompt_refs(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="github:reviewed-issue",
                kind="github_ref",
                authority="reviewed",
                source_type="github",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="methodology_hint",
                sink="prompt",
                content="GitHub issue text must not enter prompt as reviewed target truth.",
                citations=["github:reviewed-issue"],
            ),
            ContextEnvelope(
                ref="notion:confirmed-note",
                kind="notion_ref",
                authority="confirmed",
                source_type="notion",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="methodology_hint",
                sink="prompt",
                content="Notion note text must not enter prompt as confirmed target truth.",
                citations=["notion:confirmed-note"],
            ),
            ContextEnvelope(
                ref="github:engineering-note",
                kind="github_ref",
                authority="asserted",
                source_type="github",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="methodology_hint",
                sink="prompt",
                content="GitHub issue can remain labeled as engineering collaboration context.",
                citations=["github:engineering-note"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="methodology_hint",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        collaboration_refs = [item["ref"] for item in packet["sections"]["COLLABORATION_REFS"]]
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}

        self.assertEqual(collaboration_refs, ["github:engineering-note"])
        self.assertEqual(omitted_refs["github:reviewed-issue"], "collaboration_truth_like_authority")
        self.assertEqual(omitted_refs["notion:confirmed-note"], "collaboration_truth_like_authority")
        self.assertNotIn("reviewed target truth", packet["rendered"])
        self.assertNotIn("confirmed target truth", packet["rendered"])
        self.assertIn("engineering collaboration context", packet["rendered"])

    def test_context_assembler_omits_truth_like_ctfd_prompt_refs_from_import_lanes(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="ctfd:reviewed-imported-ref",
                kind="ctfd_ref",
                authority="reviewed",
                source_type="ctf_manifest",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="methodology_hint",
                sink="prompt",
                content="CTFd imported reference must not enter prompt as reviewed target truth.",
                citations=["ctfd:reviewed-imported-ref"],
            ),
            ContextEnvelope(
                ref="ctfd:asserted-imported-ref",
                kind="ctfd_ref",
                authority="asserted",
                source_type="ctf_manifest",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="methodology_hint",
                sink="prompt",
                content="CTFd imported reference can remain labeled as collaboration context.",
                citations=["ctfd:asserted-imported-ref"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="methodology_hint",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        collaboration_refs = [item["ref"] for item in packet["sections"]["COLLABORATION_REFS"]]
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}

        self.assertEqual(collaboration_refs, ["ctfd:asserted-imported-ref"])
        self.assertEqual(omitted_refs["ctfd:reviewed-imported-ref"], "ctfd_truth_like_authority")
        self.assertNotIn("reviewed target truth", packet["rendered"])
        self.assertIn("collaboration context", packet["rendered"])

__all__ = [name for name in globals() if name.endswith("Part4")]
