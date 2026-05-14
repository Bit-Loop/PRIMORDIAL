from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

try:
    from agent_chat_api.tests.support import PACKAGE_ROOT, remove_test_bin, run_handler, run_handler_raw, temporary_executable
except ModuleNotFoundError:
    from support import PACKAGE_ROOT, remove_test_bin, run_handler, run_handler_raw, temporary_executable

from agent_chat_api.config import Settings
from agent_chat_api.server import create_app


class ServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = Settings(
            workspace_root=PACKAGE_ROOT,
            codex_bin="/usr/bin/codex",
            claude_bin="/usr/bin/claude",
        )
        self.handler_cls = create_app(self.settings)

    def tearDown(self) -> None:
        remove_test_bin(PACKAGE_ROOT)

    def test_health_reports_workspace_and_providers(self) -> None:
        status, payload = run_handler(self.handler_cls, "GET", "/health")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["workspace_root"], str(PACKAGE_ROOT))
        self.assertIn("codex", payload["providers"])
        self.assertIn("claude", payload["providers"])

    def test_health_accepts_query_string(self) -> None:
        status, payload = run_handler(self.handler_cls, "GET", "/health?check=1")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])

    def test_simple_chat_dry_run_returns_claude_command(self) -> None:
        status, payload = run_handler(
            self.handler_cls,
            "POST",
            "/api/chat",
            {"provider": "claude", "prompt": "hello", "dry_run": True},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["provider"], "claude")
        self.assertTrue(payload["dry_run"])
        self.assertIn("request_id", payload)
        self.assertEqual(payload["cwd"], str(PACKAGE_ROOT))
        self.assertIn("--tools ''", payload["command"])

    def test_simple_chat_defaults_to_codex(self) -> None:
        status, payload = run_handler(
            self.handler_cls,
            "POST",
            "/api/chat",
            {"prompt": "hello", "dry_run": True},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["provider"], "codex")
        self.assertTrue(payload["dry_run"])
        self.assertIn("codex", payload["command"])

    def test_api_chat_falls_back_from_codex_refusal_to_claude(self) -> None:
        fake_codex = temporary_executable(
            PACKAGE_ROOT,
            "fake-codex-api-refusal",
            """
print("Sorry, I cannot do that.")
""",
        )
        fake_claude = temporary_executable(
            PACKAGE_ROOT,
            "fake-claude-api-fallback",
            """
print('{"result":"api fallback ok"}')
""",
        )
        with tempfile.TemporaryDirectory() as tmp:
            handler_cls = create_app(
                Settings(
                    workspace_root=PACKAGE_ROOT,
                    codex_bin=str(fake_codex),
                    claude_bin=str(fake_claude),
                    audit_log_path=Path(tmp) / "provider-audit.jsonl",
                )
            )
            status, payload = run_handler(handler_cls, "POST", "/api/chat", {"prompt": "hello", "safe_guard": False})

        self.assertEqual(status, 200)
        self.assertEqual(payload["provider"], "claude")
        self.assertEqual(payload["text"], "api fallback ok")
        self.assertTrue(payload["fallback"]["used"])
        self.assertEqual(payload["fallback"]["attempts"][0]["provider"], "codex")
        self.assertEqual(payload["audit_events"][0]["reason"], "refusal_response")

    def test_openai_compatible_endpoint_accepts_provider_prefixed_model(self) -> None:
        status, payload = run_handler(
            self.handler_cls,
            "POST",
            "/v1/chat/completions",
            {
                "model": "codex:gpt-5.5",
                "messages": [{"role": "user", "content": "hello"}],
                "dry_run": True,
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["object"], "chat.completion")
        self.assertEqual(payload["provider"], "codex")
        self.assertEqual(payload["choices"][0]["message"]["role"], "assistant")
        self.assertTrue(payload["provider_meta"]["dry_run"])
        self.assertIn("request_id", payload["provider_meta"])

    def test_post_route_accepts_query_string(self) -> None:
        status, payload = run_handler(
            self.handler_cls,
            "POST",
            "/api/chat?trace=1",
            {"provider": "claude", "prompt": "hello", "dry_run": True},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["provider"], "claude")

    def test_auth_blocks_missing_bearer_token(self) -> None:
        handler_cls = create_app(Settings(workspace_root=PACKAGE_ROOT, api_key="secret"))
        status, payload = run_handler(handler_cls, "POST", "/api/chat", {"prompt": "hello", "dry_run": True})
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "unauthorized")

    def test_auth_accepts_expected_bearer_token(self) -> None:
        handler_cls = create_app(Settings(workspace_root=PACKAGE_ROOT, api_key="secret"))
        status, payload = run_handler(
            handler_cls,
            "POST",
            "/api/chat",
            {"prompt": "hello", "dry_run": True},
            headers={"Authorization": "Bearer secret"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["dry_run"])

    def test_api_chat_streams_sse_events(self) -> None:
        fake_claude = temporary_executable(
            PACKAGE_ROOT,
            "fake-claude-stream",
            """
print('{"type":"content_block_delta","delta":{"text":"hello"}}')
print('{"type":"result","result":"hello","session_id":"claude-session-1"}')
""",
        )
        handler_cls = create_app(Settings(workspace_root=PACKAGE_ROOT, claude_bin=str(fake_claude)))
        status, headers, body = run_handler_raw(
            handler_cls,
            "POST",
            "/api/chat",
            {"provider": "claude", "prompt": "hello", "stream": True},
        )
        self.assertEqual(status, 200)
        self.assertIn("text/event-stream", headers["content-type"])
        self.assertIn("event: meta", body)
        self.assertIn("event: delta", body)
        self.assertIn("hello", body)
        self.assertIn("event: done", body)

    def test_openai_compatible_stream_returns_sse_chunks(self) -> None:
        fake_claude = temporary_executable(
            PACKAGE_ROOT,
            "fake-claude-openai-stream",
            """
print('{"type":"content_block_delta","delta":{"text":"hello"}}')
print('{"type":"result","result":"hello","session_id":"claude-session-1"}')
""",
        )
        handler_cls = create_app(Settings(workspace_root=PACKAGE_ROOT, claude_bin=str(fake_claude)))
        status, headers, body = run_handler_raw(
            handler_cls,
            "POST",
            "/v1/chat/completions",
            {"provider": "claude", "messages": [{"role": "user", "content": "hello"}], "stream": True},
        )
        self.assertEqual(status, 200)
        self.assertIn("text/event-stream", headers["content-type"])
        self.assertIn("chat.completion.chunk", body)
        self.assertIn('"content":"hello"', body)
        self.assertIn("data: [DONE]", body)

    def test_rate_limit_blocks_live_requests_after_limit(self) -> None:
        fake_claude = temporary_executable(
            PACKAGE_ROOT,
            "fake-claude-rate",
            """
print('{"result":"ok","session_id":"claude-session-1"}')
""",
        )
        settings = Settings(workspace_root=PACKAGE_ROOT, claude_bin=str(fake_claude), rate_limit_requests=1)
        handler_cls = create_app(settings)
        first_status, first_payload = run_handler(handler_cls, "POST", "/api/chat", {"provider": "claude", "prompt": "hello"})
        second_status, second_headers, second_body = run_handler_raw(handler_cls, "POST", "/api/chat", {"provider": "claude", "prompt": "hello"})
        self.assertEqual(first_status, 200)
        self.assertEqual(first_payload["text"], "ok")
        self.assertEqual(second_status, 429)
        self.assertIn("x-ratelimit-limit", second_headers)
        self.assertIn("rate_limited", second_body)

    def test_dry_run_is_exempt_from_rate_limit(self) -> None:
        settings = Settings(workspace_root=PACKAGE_ROOT, rate_limit_requests=1)
        handler_cls = create_app(settings)
        for _index in range(3):
            status, payload = run_handler(handler_cls, "POST", "/api/chat", {"prompt": "hello", "dry_run": True})
            self.assertEqual(status, 200)
            self.assertTrue(payload["dry_run"])

    def test_unknown_route_returns_404(self) -> None:
        status, payload = run_handler(self.handler_cls, "GET", "/missing")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "not_found")


if __name__ == "__main__":
    unittest.main()
