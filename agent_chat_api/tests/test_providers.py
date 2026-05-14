from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

try:
    from agent_chat_api.tests.support import PACKAGE_ROOT, remove_test_bin, temporary_executable
except ModuleNotFoundError:
    from support import PACKAGE_ROOT, remove_test_bin, temporary_executable

from agent_chat_api.config import Settings
from agent_chat_api.providers import (
    ChatRequest,
    ChatRunner,
    ProviderError,
    ProviderResult,
    RequestError,
    _parse_claude_stdout,
    messages_to_prompt,
    request_from_payload,
)


class ProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = PACKAGE_ROOT
        self.settings = Settings(
            workspace_root=self.root,
            codex_bin="/usr/bin/codex",
            claude_bin="/usr/bin/claude",
        )
        self.runner = ChatRunner(self.settings)

    def tearDown(self) -> None:
        remove_test_bin(self.root)

    def test_messages_to_prompt_preserves_roles(self) -> None:
        prompt = messages_to_prompt(
            [
                {"role": "system", "content": "Be concise."},
                {"role": "user", "content": "Hello"},
            ]
        )
        self.assertIn("SYSTEM:\nBe concise.", prompt)
        self.assertIn("USER:\nHello", prompt)

    def test_model_prefix_selects_provider(self) -> None:
        request = request_from_payload({"model": "codex:gpt-5.5", "prompt": "x", "dry_run": True}, "claude")
        self.assertEqual(request.provider, "codex")
        self.assertEqual(request.model, "gpt-5.5")

    def test_payload_rejects_non_list_messages(self) -> None:
        with self.assertRaises(RequestError):
            request_from_payload({"messages": "hello"}, "claude")

    def test_payload_rejects_bad_integer_fields(self) -> None:
        with self.assertRaises(RequestError):
            request_from_payload({"prompt": "hello", "timeout_seconds": "soon"}, "claude")

    def test_payload_parses_string_booleans_deliberately(self) -> None:
        request = request_from_payload(
            {
                "prompt": "hello",
                "dry_run": "false",
                "include_raw": "true",
                "allow_tools": "no",
                "safe_guard": "off",
                "codex_ephemeral": "1",
            },
            "claude",
        )
        self.assertFalse(request.dry_run)
        self.assertTrue(request.include_raw)
        self.assertFalse(request.allow_tools)
        self.assertFalse(request.safe_guard)
        self.assertTrue(request.codex_ephemeral)

    def test_payload_rejects_ambiguous_boolean_values(self) -> None:
        with self.assertRaises(RequestError):
            request_from_payload({"prompt": "hello", "dry_run": "sometimes"}, "claude")

    def test_claude_command_disables_tools_by_default(self) -> None:
        command, warnings = self.runner.build_command(
            ChatRequest(provider="claude", prompt="hello"),
            "claude",
            self.root,
        )
        self.assertEqual(warnings, [])
        self.assertIn("-p", command)
        self.assertIn("--output-format", command)
        self.assertIn("json", command)
        self.assertNotIn("--max-turns", command)
        self.assertEqual(command[command.index("--tools") + 1], "")

    def test_claude_command_allows_explicit_tool_mode(self) -> None:
        command, warnings = self.runner.build_command(
            ChatRequest(provider="claude", prompt="hello", allow_tools=True, claude_tools="Read", claude_permission_mode="default"),
            "claude",
            self.root,
        )
        self.assertEqual(warnings, [])
        self.assertEqual(command[command.index("--tools") + 1], "Read")
        self.assertEqual(command[command.index("--permission-mode") + 1], "default")

    def test_claude_max_turns_emits_warning_without_cli_flag(self) -> None:
        command, warnings = self.runner.build_command(
            ChatRequest(provider="claude", prompt="hello", claude_max_turns=3),
            "claude",
            self.root,
        )
        self.assertNotIn("--max-turns", command)
        self.assertTrue(warnings)

    def test_codex_command_uses_read_only_sandbox(self) -> None:
        command, warnings = self.runner.build_command(
            ChatRequest(provider="codex", prompt="hello"),
            "codex",
            self.root,
        )
        self.assertIn("exec", command)
        self.assertIn("--sandbox", command)
        self.assertEqual(command[command.index("--sandbox") + 1], "read-only")
        self.assertTrue(warnings)
        self.assertEqual(command[-1], "-")

    def test_codex_workspace_write_sandbox_can_be_requested(self) -> None:
        command, _warnings = self.runner.build_command(
            ChatRequest(provider="codex", prompt="hello", codex_sandbox="workspace-write", allow_tools=True),
            "codex",
            self.root,
        )
        self.assertEqual(command[command.index("--sandbox") + 1], "workspace-write")

    def test_codex_danger_sandbox_is_denied_by_default(self) -> None:
        with self.assertRaises(RequestError):
            self.runner.build_command(
                ChatRequest(provider="codex", prompt="hello", codex_sandbox="danger-full-access"),
                "codex",
                self.root,
            )

    def test_invalid_provider_is_rejected(self) -> None:
        with self.assertRaises(RequestError):
            self.runner.run(ChatRequest(provider="unknown", prompt="hello", dry_run=True))

    def test_cwd_is_confined_to_workspace_root(self) -> None:
        with self.assertRaises(RequestError):
            self.runner.resolve_cwd("/tmp")

    def test_child_cwd_under_workspace_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.root) as tmp:
            self.assertEqual(self.runner.resolve_cwd(tmp), Path(tmp).resolve())

    def test_dry_run_does_not_invoke_provider(self) -> None:
        result = self.runner.run(ChatRequest(provider="claude", prompt="hello", dry_run=True))
        self.assertTrue(result.dry_run)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.text, "")
        self.assertIsNotNone(result.request_id)

    def test_public_dict_redacts_raw_provider_identifiers(self) -> None:
        result = ProviderResult(
            provider="claude",
            model=None,
            text="ok",
            exit_code=0,
            elapsed_seconds=1.0,
            command=["claude"],
            cwd=str(self.root),
            stdout='{"session_id":"abc","uuid":"def","result":"ok"}',
            stderr="session id: 019e254f-2f20-7d61-9aa5-aa10f6aa4ced",
            raw_json={"session_id": "abc", "nested": {"uuid": "def"}, "result": "ok"},
            request_id="req-1",
        )
        payload = result.public_dict(include_raw=True)
        self.assertEqual(payload["request_id"], "req-1")
        self.assertIn("[redacted]", payload["stdout"])
        self.assertIn("[redacted]", payload["stderr"])
        self.assertEqual(payload["raw_json"]["session_id"], "[redacted]")
        self.assertEqual(payload["raw_json"]["nested"]["uuid"], "[redacted]")
        self.assertEqual(payload["raw_json"]["result"], "ok")

    def test_public_dict_excludes_raw_payload_by_default(self) -> None:
        result = ProviderResult(
            provider="claude",
            model=None,
            text="ok",
            exit_code=0,
            elapsed_seconds=1.0,
            command=["claude"],
            cwd=str(self.root),
            stdout="secret",
            stderr="secret",
            raw_json={"session_id": "abc"},
            request_id="req-1",
        )
        payload = result.public_dict()
        self.assertNotIn("stdout", payload)
        self.assertNotIn("stderr", payload)
        self.assertNotIn("raw_json", payload)
        self.assertEqual(payload["request_id"], "req-1")

    def test_build_prompt_combines_guard_system_prompt_and_messages(self) -> None:
        prompt = self.runner.build_prompt(
            ChatRequest(
                prompt="Raw prompt",
                system_prompt="System context",
                messages=[{"role": "user", "content": "Message prompt"}],
            )
        )
        self.assertIn("Do not install packages", prompt)
        self.assertIn("SYSTEM:\nSystem context", prompt)
        self.assertIn("Raw prompt", prompt)
        self.assertIn("USER:\nMessage prompt", prompt)

    def test_build_prompt_can_disable_guard(self) -> None:
        prompt = self.runner.build_prompt(ChatRequest(prompt="Only this", safe_guard=False))
        self.assertEqual(prompt, "Only this")

    def test_build_prompt_rejects_empty_or_oversized_prompt(self) -> None:
        with self.assertRaises(RequestError):
            self.runner.build_prompt(ChatRequest())
        runner = ChatRunner(Settings(workspace_root=self.root, max_prompt_chars=3))
        with self.assertRaises(RequestError):
            runner.build_prompt(ChatRequest(prompt="abcd"))

    def test_timeout_is_capped_and_validated(self) -> None:
        runner = ChatRunner(Settings(workspace_root=self.root, default_timeout_seconds=10, max_timeout_seconds=20))
        self.assertEqual(runner._timeout(None), 10)
        self.assertEqual(runner._timeout(99), 20)
        with self.assertRaises(RequestError):
            runner._timeout(0)

    def test_parse_claude_stdout_handles_json_and_plain_text(self) -> None:
        text, raw = _parse_claude_stdout('{"result":"hello"}')
        self.assertEqual(text, "hello")
        self.assertIsInstance(raw, dict)
        text, raw = _parse_claude_stdout('{"content":[{"type":"text","text":"one"},{"type":"text","text":"two"}]}')
        self.assertEqual(text, "one\ntwo")
        self.assertIsInstance(raw, dict)
        text, raw = _parse_claude_stdout("plain")
        self.assertEqual(text, "plain")
        self.assertIsNone(raw)

    def test_run_uses_fake_claude_binary_without_live_model_call(self) -> None:
        fake_claude = temporary_executable(
            self.root,
            "fake-claude",
            """
stdin = sys.stdin.read()
print('{"result":"fake claude saw ' + str(len(stdin)) + ' chars"}')
""",
        )
        runner = ChatRunner(Settings(workspace_root=self.root, claude_bin=str(fake_claude)))
        result = runner.run(ChatRequest(provider="claude", prompt="hello", safe_guard=False))
        self.assertEqual(result.text, "fake claude saw 5 chars")
        self.assertEqual(result.exit_code, 0)

    def test_run_uses_fake_codex_binary_without_live_model_call(self) -> None:
        fake_codex = temporary_executable(
            self.root,
            "fake-codex",
            """
stdin = sys.stdin.read()
print('fake codex saw ' + str(len(stdin)) + ' chars')
""",
        )
        runner = ChatRunner(Settings(workspace_root=self.root, codex_bin=str(fake_codex)))
        result = runner.run(ChatRequest(provider="codex", prompt="hello", safe_guard=False))
        self.assertEqual(result.text, "fake codex saw 5 chars")
        self.assertEqual(result.exit_code, 0)

    def test_provider_nonzero_exit_becomes_provider_error(self) -> None:
        fake_claude = temporary_executable(
            self.root,
            "fake-claude-fail",
            """
sys.stderr.write('provider failed')
raise SystemExit(7)
""",
        )
        runner = ChatRunner(Settings(workspace_root=self.root, claude_bin=str(fake_claude)))
        with self.assertRaises(ProviderError) as raised:
            runner.run(ChatRequest(provider="claude", prompt="hello", safe_guard=False))
        self.assertEqual(raised.exception.status_code, 502)
        self.assertIn("provider failed", str(raised.exception))

    def test_fallback_uses_claude_after_codex_refusal_and_audits(self) -> None:
        fake_codex = temporary_executable(
            self.root,
            "fake-codex-refusal",
            """
print("Sorry, I cannot do that.")
""",
        )
        fake_claude = temporary_executable(
            self.root,
            "fake-claude-fallback",
            """
print('{"result":"fallback ok"}')
""",
        )
        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / "provider-audit.jsonl"
            runner = ChatRunner(
                Settings(
                    workspace_root=self.root,
                    codex_bin=str(fake_codex),
                    claude_bin=str(fake_claude),
                    audit_log_path=audit_path,
                )
            )
            result = runner.run(ChatRequest(provider="codex", prompt="hello", safe_guard=False, fallback=True))

            self.assertEqual(result.provider, "claude")
            self.assertEqual(result.text, "fallback ok")
            self.assertEqual(len(result.fallback_attempts), 1)
            self.assertEqual(result.fallback_attempts[0]["provider"], "codex")
            self.assertEqual(result.fallback_attempts[0]["reason"], "refusal_response")
            audit_lines = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(audit_lines[0]["type"], "provider_refusal")
            self.assertEqual(audit_lines[0]["reason"], "refusal_response")
            self.assertNotIn("hello", audit_lines[0]["snippet"])

    def test_fallback_uses_claude_after_codex_quota_error(self) -> None:
        fake_codex = temporary_executable(
            self.root,
            "fake-codex-quota",
            """
sys.stderr.write("usage limit reached")
raise SystemExit(1)
""",
        )
        fake_claude = temporary_executable(
            self.root,
            "fake-claude-after-quota",
            """
print('{"result":"quota fallback ok"}')
""",
        )
        with tempfile.TemporaryDirectory() as tmp:
            runner = ChatRunner(
                Settings(
                    workspace_root=self.root,
                    codex_bin=str(fake_codex),
                    claude_bin=str(fake_claude),
                    audit_log_path=Path(tmp) / "provider-audit.jsonl",
                )
            )
            result = runner.run(ChatRequest(provider="codex", prompt="hello", safe_guard=False, fallback=True))

        self.assertEqual(result.provider, "claude")
        self.assertEqual(result.text, "quota fallback ok")
        self.assertEqual(result.fallback_attempts[0]["reason"], "quota_exhausted")

    def test_final_fallback_when_all_providers_refuse(self) -> None:
        fake_codex = temporary_executable(
            self.root,
            "fake-codex-refuses",
            """
print("I can't help with that.")
""",
        )
        fake_claude = temporary_executable(
            self.root,
            "fake-claude-refuses",
            """
print('{"result":"I cannot assist with that request."}')
""",
        )
        with tempfile.TemporaryDirectory() as tmp:
            runner = ChatRunner(
                Settings(
                    workspace_root=self.root,
                    codex_bin=str(fake_codex),
                    claude_bin=str(fake_claude),
                    audit_log_path=Path(tmp) / "provider-audit.jsonl",
                )
            )
            result = runner.run(ChatRequest(provider="codex", prompt="hello", safe_guard=False, fallback=True))

        self.assertEqual(result.provider, "wrapper")
        self.assertTrue(result.final_fallback)
        self.assertIn("No synthetic model answer was generated", result.text)
        self.assertEqual([item["provider"] for item in result.fallback_attempts], ["codex", "claude"])


if __name__ == "__main__":
    unittest.main()
