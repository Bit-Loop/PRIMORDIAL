from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope, ContextSinkValidator

class ContextReportWriterTestsBase(unittest.TestCase):
    def _envelope(
        self,
        ref: str,
        kind: str,
        source_type: str,
        content: str,
        citations: list[str],
        **metadata: object,
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind=kind,
            authority="reviewed" if kind == "finding" else "asserted",
            source_type=source_type,
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="report_generation",
            sink="prompt",
            content=content,
            citations=citations,
            metadata=metadata,
        )

__all__ = [name for name in globals() if not name.startswith("__")]
