from __future__ import annotations

import unittest

from primordial.core.context import CitationValidator, ContextEnvelope

class ContextCitationValidatorTestsBase(unittest.TestCase):
    def _target_fact(
        self,
        ref: str,
        citations: list[str],
        *,
        advisory_claim: bool = False,
    ) -> ContextEnvelope:
        metadata = {"contains_target_fact": True}
        if advisory_claim:
            metadata["advisory_claim"] = True
        return ContextEnvelope(
            ref=ref,
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            target_id="target-a",
            purpose="target_state_answer",
            sink="report",
            content="The target is running Apache 2.4.49.",
            citations=citations,
            metadata=metadata,
        )

    def _advisory_claim(self, ref: str, citations: list[str]) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind="model_summary",
            authority="derived",
            source_type="ai_output",
            purpose="operator_answer",
            sink="report",
            content="Advisory methodology says to retry routing checks.",
            citations=citations,
            metadata={"advisory_claim": True},
        )

__all__ = [name for name in globals() if not name.startswith("__")]
