from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope


class ContextAssemblerRagCitationRefTests(unittest.TestCase):
    def test_assembler_omits_rag_context_with_unresolved_rag_citation(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:indexed-method",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            target_id="target-a",
            active_generation_id="generation:2",
            purpose="operator_answer",
            sink="prompt",
            content="Advisory method text with a fabricated cross-reference.",
            citations=["rag:indexed-method", "rag:made-up"],
        )

        packet = ContextAssembler().assemble(
            [envelope],
            purpose="operator_answer",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        self.assertEqual(packet["omitted"], [{"ref": "rag:indexed-method", "reason": "invalid_citation"}])


if __name__ == "__main__":
    unittest.main()
