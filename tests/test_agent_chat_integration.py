from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest

from primordial.core.domain.enums import (
    AgentRole,
    MethodologyPhase,
    ProviderRoute,
    ScopeProfile,
    TaskKind,
)
from primordial.core.domain.models import RouteSelection, Target, Task
from primordial.core.providers.agent_chat import (
    AgentChatClient,
    AgentChatPremiumReviewRunner,
    AgentChatResponse,
    AgentChatSettings,
    parse_review_json,
)


class AgentChatClientTests(unittest.TestCase):
    def test_chat_posts_to_wrapper_with_auth_and_returns_provider_metadata(self) -> None:
        captured: dict[str, object] = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                captured["authorization"] = self.headers.get("Authorization")
                captured["payload"] = json.loads(self.rfile.read(length).decode("utf-8"))
                body = json.dumps(
                    {
                        "request_id": "req-test",
                        "provider": "claude",
                        "model": "claude-sonnet-4",
                        "text": "{\"confidence\": 0.7}",
                        "exit_code": 0,
                        "elapsed_seconds": 1.25,
                        "cwd": "/tmp",
                        "conversation_id": "conv-test",
                        "session_resumed": False,
                        "warnings": [],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base_url = f"http://127.0.0.1:{server.server_address[1]}"
            client = AgentChatClient(
                AgentChatSettings(
                    base_url=base_url,
                    api_key="secret",
                    provider="claude",
                    model="claude-sonnet-4",
                    timeout_seconds=5,
                )
            )

            response = client.chat(prompt="review this", conversation_id="conv-test")
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()

        self.assertEqual(response.request_id, "req-test")
        self.assertEqual(response.provider, "claude")
        self.assertEqual(captured["authorization"], "Bearer secret")
        payload = captured["payload"]
        self.assertIsInstance(payload, dict)
        self.assertEqual(payload["provider"], "claude")
        self.assertEqual(payload["conversation_id"], "conv-test")
        self.assertFalse(payload["allow_tools"])


class AgentChatPremiumReviewRunnerTests(unittest.TestCase):
    def test_runner_persists_structured_remote_review_as_admissible_evidence(self) -> None:
        target = Target(
            handle="helix.htb",
            display_name="Helix",
            profile=ScopeProfile.HACK_THE_BOX,
        )
        review = {
            "recommended_next_actions": [
                {
                    "title": "Re-run bounded service discovery",
                    "rationale": "Evidence e1 is stale for the active target generation.",
                    "confidence": 0.76,
                    "primitive_hint": "tcp-service-discovery",
                    "evidence_refs": ["e1"],
                }
            ],
            "missing_evidence": [],
            "invalid_existing_tasks": [],
            "primitive_gaps": [],
            "confidence": 0.76,
            "rationale_with_evidence_refs": [{"summary": "stale services", "evidence_refs": ["e1"]}],
        }

        class FakeClient:
            settings = AgentChatSettings(provider="claude", timeout_seconds=5)

            def chat(self, **kwargs: object) -> AgentChatResponse:
                self.kwargs = kwargs
                return AgentChatResponse(
                    provider="claude",
                    model="claude-sonnet-4",
                    text=json.dumps(review),
                    exit_code=0,
                    elapsed_seconds=0.1,
                    request_id="req-review",
                    conversation_id=str(kwargs.get("conversation_id")),
                    prompt_tokens=120,
                    completion_tokens=40,
                    estimated_cost_usd=0.12,
                )

        client = FakeClient()
        cost_records: list[dict[str, object]] = []
        runner = AgentChatPremiumReviewRunner(
            client,
            target_loader=lambda target_id: target,
            remote_cost_recorder=lambda **kwargs: cost_records.append(kwargs),
        )
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.ANALYSIS,
            kind=TaskKind.REVIEW_PREMIUM_ESCALATION,
            title="Premium planner review requested",
            summary="Resolve planner uncertainty.",
            role=AgentRole.CLAUDE_REVIEWER,
            evidence_refs=["e1"],
            provider_route=ProviderRoute.REMOTE_PREMIUM,
            provider_model="claude-sonnet-4",
            metadata={
                "escalation_package": {
                    "expected_output_type": "planner_remote_review_v1",
                    "evidence_refs": ["e1"],
                    "metadata": {
                        "required_output": {
                            "recommended_next_actions": "array<object>",
                            "missing_evidence": "array<string>",
                            "invalid_existing_tasks": "array<object>",
                            "primitive_gaps": "array<string>",
                            "confidence": "number",
                            "rationale_with_evidence_refs": "array<object>",
                        }
                    },
                }
            },
        )
        selection = RouteSelection(route=ProviderRoute.REMOTE_PREMIUM, model_name="claude-sonnet-4", rationale="test")

        offer = runner.create_offer(task, selection)
        self.assertIsNotNone(offer)
        assert offer is not None
        self.assertTrue(runner.accept_offer(offer.offer_id, task, selection))
        result = runner.execute_assignment(offer.offer_id, task, None)

        self.assertTrue(result.success)
        self.assertEqual(result.evidence[0].metadata["kind"], "premium_review_result")
        self.assertTrue(result.evidence[0].metadata["structured_output"])
        self.assertEqual(result.evidence[0].metadata["review"]["confidence"], 0.76)
        self.assertEqual(result.traces[0].status, "completed")
        self.assertTrue(result.traces[0].metadata["remote_cost"]["recorded"])
        self.assertEqual(cost_records[0]["estimated_cost_usd"], 0.12)
        self.assertEqual(cost_records[0]["prompt_tokens"], 120)
        self.assertEqual(client.kwargs["conversation_id"], f"primordial:{task.id}")
        self.assertIsNone(client.kwargs["model"])

    def test_parse_review_json_accepts_markdown_wrapped_json(self) -> None:
        parsed = parse_review_json("```json\n{\"confidence\": 0.8}\n```")

        self.assertEqual(parsed, {"confidence": 0.8})


if __name__ == "__main__":
    unittest.main()
