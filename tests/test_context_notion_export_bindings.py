from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator


class ContextNotionExportBindingTests(unittest.TestCase):
    def test_notion_export_quarantines_wrong_target_and_stale_model_target_facts(self) -> None:
        envelopes = [
            self._target_fact(
                ref="model:current-export-fact",
                target_id="target-a",
                active_generation_id="generation:2",
                content="Current target evidence-backed summary.",
            ),
            self._target_fact(
                ref="model:wrong-target-export-fact",
                target_id="target-b",
                active_generation_id="generation:2",
                content="Wrong target evidence-backed summary.",
            ),
            self._target_fact(
                ref="model:stale-export-fact",
                target_id="target-a",
                active_generation_id="generation:1",
                content="Stale generation evidence-backed summary.",
            ),
            self._target_fact(
                ref="model:missing-generation-export-fact",
                target_id="target-a",
                active_generation_id="",
                content="Missing generation evidence-backed summary.",
            ),
        ]

        result = ContextSinkValidator().validate("notion_export", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, ["model:current-export-fact"])
        self.assertEqual(
            result.quarantined_refs,
            [
                "model:missing-generation-export-fact",
                "model:stale-export-fact",
                "model:wrong-target-export-fact",
            ],
        )
        self.assertTrue(any("wrong_target" in error for error in result.errors))
        self.assertTrue(any("stale_generation" in error for error in result.errors))
        self.assertTrue(any("missing_generation_binding" in error for error in result.errors))

    def _target_fact(
        self,
        *,
        ref: str,
        target_id: str,
        active_generation_id: str,
        content: str,
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id=target_id,
            active_generation_id=active_generation_id,
            purpose="export",
            sink="notion_export",
            content=content,
            citations=["evidence:http-banner"],
            metadata={
                "contains_target_fact": True,
                "current_target_id": "target-a",
                "current_active_generation_id": "generation:2",
                "source_refs": ["evidence:http-banner"],
            },
        )


if __name__ == "__main__":
    unittest.main()
