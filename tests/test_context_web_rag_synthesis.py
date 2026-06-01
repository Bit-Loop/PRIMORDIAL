from __future__ import annotations

import json
import unittest

from primordial.core.web.app import PrimordialWebApp


class _SynthesisRuntime:
    def __init__(self) -> None:
        self.rag_search_calls = 0
        self.last_synthesize: dict[str, object] = {}

    def rag_search(self, query: str, **kwargs: object) -> dict[str, object]:
        self.rag_search_calls += 1
        return {
            "results": [
                {
                    "chunk_id": "method-1",
                    "citation_id": "rag:method-1",
                    "text": "Methodology context.",
                    "metadata": {"domain": "methodology_standards"},
                }
            ]
        }

    def synthesize_rag_answer(
        self,
        query: str,
        *,
        mode: str,
        retrieved_chunks: list[dict[str, object]] | None = None,
        safety_context: dict[str, object] | None = None,
    ) -> dict[str, object]:
        self.last_synthesize = {
            "query": query,
            "mode": mode,
            "retrieved_chunks": retrieved_chunks,
            "safety_context": safety_context,
        }
        if retrieved_chunks is None:
            return {
                "ok": False,
                "status": "operational_context_required",
                "error": "retrieved_chunks are required for operational RAG synthesis",
            }
        return {"ok": True, "status": "synthesized", "retrieved_count": len(retrieved_chunks)}


class WebRagSynthesisBoundaryTests(unittest.TestCase):
    def test_operational_synthesis_does_not_prefetch_unscoped_rag(self) -> None:
        runtime = _SynthesisRuntime()
        app = PrimordialWebApp(runtime)  # type: ignore[arg-type]

        response = app.dispatch(
            "POST",
            "/api/rag/synthesize",
            json.dumps({"query": "What should the planner do next?", "mode": "planner"}).encode("utf-8"),
        )

        body = json.loads(response.body)
        self.assertEqual(response.status, 200)
        self.assertEqual(body["status"], "operational_context_required")
        self.assertEqual(runtime.rag_search_calls, 0)
        self.assertIsNone(runtime.last_synthesize["retrieved_chunks"])

    def test_export_synthesis_does_not_prefetch_unscoped_rag(self) -> None:
        runtime = _SynthesisRuntime()
        app = PrimordialWebApp(runtime)  # type: ignore[arg-type]

        response = app.dispatch(
            "POST",
            "/api/rag/synthesize",
            json.dumps({"query": "Prepare a Notion export summary.", "mode": "export"}).encode("utf-8"),
        )

        body = json.loads(response.body)
        self.assertEqual(response.status, 200)
        self.assertEqual(body["status"], "operational_context_required")
        self.assertEqual(runtime.rag_search_calls, 0)
        self.assertIsNone(runtime.last_synthesize["retrieved_chunks"])

    def test_operator_answer_synthesis_does_not_prefetch_unscoped_rag(self) -> None:
        runtime = _SynthesisRuntime()
        app = PrimordialWebApp(runtime)  # type: ignore[arg-type]

        response = app.dispatch(
            "POST",
            "/api/rag/synthesize",
            json.dumps({"query": "Answer the operator about current target state.", "mode": "operator_answer"}).encode(
                "utf-8"
            ),
        )

        body = json.loads(response.body)
        self.assertEqual(response.status, 200)
        self.assertEqual(body["status"], "operational_context_required")
        self.assertEqual(runtime.rag_search_calls, 0)
        self.assertIsNone(runtime.last_synthesize["retrieved_chunks"])

    def test_non_operational_synthesis_can_prefetch_advisory_rag(self) -> None:
        runtime = _SynthesisRuntime()
        app = PrimordialWebApp(runtime)  # type: ignore[arg-type]

        response = app.dispatch(
            "POST",
            "/api/rag/synthesize",
            json.dumps({"query": "Explain BOLA", "mode": "grounded_answer"}).encode("utf-8"),
        )

        body = json.loads(response.body)
        self.assertEqual(response.status, 200)
        self.assertEqual(body["status"], "synthesized")
        self.assertEqual(runtime.rag_search_calls, 1)
        self.assertEqual(body["retrieved_count"], 1)


if __name__ == "__main__":
    unittest.main()
