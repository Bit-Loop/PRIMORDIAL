from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope

class ContextAssemblerSourceBoundaryTestsBase(unittest.TestCase):
    def _envelope(
        self,
        ref: str,
        kind: str,
        authority: str,
        source_type: str,
        citations: list[str],
        metadata: dict[str, object] | None = None,
        sink: str = "prompt",
        target_id: str = "target-a",
        active_generation_id: str = "generation:2",
    ) -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind=kind,
            authority=authority,
            source_type=source_type,
            target_id=target_id,
            active_generation_id=active_generation_id,
            purpose="planner",
            sink=sink,
            content=f"{ref} prompt context.",
            citations=citations,
            metadata=metadata or {},
        )

__all__ = [name for name in globals() if not name.startswith("__")]
