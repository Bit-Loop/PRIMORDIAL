from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope, ContextSinkValidator


class ContextActionTraceTests(unittest.TestCase):
    def test_recent_action_trace_kinds_are_not_model_derived(self) -> None:
        envelopes = [
            self._trace("trace:primitive-run", "primitive_run", "Primitive completed."),
            self._trace("trace:task-outcome", "task_outcome", "Task finished with no findings."),
            self._trace("trace:blocked-action", "blocked_action", "Policy blocked credential validation."),
            self._trace("trace:failure", "failure_trace", "Parser failed on malformed service output."),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="planner",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(
            [item["ref"] for item in packet["sections"]["RECENT_ACTION_TRACE"]],
            ["trace:primitive-run", "trace:task-outcome", "trace:blocked-action", "trace:failure"],
        )
        self.assertEqual(packet["sections"]["MODEL_DERIVED"], [])
        self.assertIn("RECENT_ACTION_TRACE", packet["rendered"])
        self.assertNotIn("MODEL_DERIVED", packet["rendered"])

    def test_rag_index_rejects_recent_action_trace_lanes(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:methodology",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="methodology_hint",
                sink="rag_index",
                content="General methodology remains valid advisory RAG material.",
                citations=["rag:methodology"],
            ),
            self._rag_index_trace("trace:primitive-run-to-rag", "primitive_run", "tool_output"),
            self._rag_index_trace("trace:task-outcome-to-rag", "task_outcome", "runtime_state"),
            self._rag_index_trace("trace:blocked-action-to-rag", "blocked_action", "runtime_state"),
            self._rag_index_trace("trace:failure-to-rag", "failure_trace", "tool_output"),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["rag:methodology"])
        self.assertEqual(
            result.rejected_refs,
            [
                "trace:blocked-action-to-rag",
                "trace:failure-to-rag",
                "trace:primitive-run-to-rag",
                "trace:task-outcome-to-rag",
            ],
        )
        self.assertTrue(any("recent action trace lane material" in error for error in result.errors))

    def _trace(self, ref: str, kind: str, content: str) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind=kind,
            authority="observed",
            source_type="runtime_state",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="planner",
            sink="prompt",
            content=content,
            citations=[ref],
        )

    def _rag_index_trace(self, ref: str, kind: str, source_type: str) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind=kind,
            authority="asserted",
            source_type=source_type,
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="cleanup",
            sink="rag_index",
            content="Operational trace material must not become active advisory RAG.",
            citations=[ref],
        )


if __name__ == "__main__":
    unittest.main()
