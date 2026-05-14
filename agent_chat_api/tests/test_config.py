from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from agent_chat_api.tests.support import PACKAGE_ROOT
except ModuleNotFoundError:
    from support import PACKAGE_ROOT

from agent_chat_api.config import Settings, _env_bool, _env_int, default_workspace_root


class ConfigTests(unittest.TestCase):
    def test_default_workspace_root_is_subfolder(self) -> None:
        self.assertEqual(default_workspace_root(), PACKAGE_ROOT)

    def test_settings_from_env_uses_subfolder_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings.from_env()
        self.assertEqual(settings.workspace_root, PACKAGE_ROOT)
        self.assertEqual(settings.host, "127.0.0.1")
        self.assertEqual(settings.port, 8787)
        self.assertEqual(settings.default_provider, "codex")
        self.assertEqual(settings.fallback_providers, ("codex", "claude"))
        self.assertTrue(settings.provider_fallback_enabled)

    def test_settings_from_env_reads_runtime_options(self) -> None:
        env = {
            "CHAT_API_HOST": "0.0.0.0",
            "CHAT_API_PORT": "9999",
            "CHAT_API_KEY": "secret",
            "CHAT_API_WORKSPACE_ROOT": str(PACKAGE_ROOT),
            "CHAT_API_ALLOW_ANY_CWD": "true",
            "CHAT_API_DEFAULT_PROVIDER": "codex",
            "CHAT_API_FALLBACK_PROVIDERS": "codex,claude",
            "CHAT_API_PROVIDER_FALLBACK_ENABLED": "false",
            "CHAT_API_TIMEOUT_SECONDS": "12",
            "CHAT_API_MAX_TIMEOUT_SECONDS": "34",
            "CHAT_API_MAX_PROMPT_CHARS": "56",
            "CHAT_API_CODEX_BIN": "/tmp/codex-test",
            "CHAT_API_CLAUDE_BIN": "/tmp/claude-test",
            "CHAT_API_ALLOW_DANGEROUS_SANDBOXES": "1",
            "CHAT_API_SESSION_STORE": str(PACKAGE_ROOT / "runtime" / "custom-sessions.json"),
            "CHAT_API_AUDIT_LOG": str(PACKAGE_ROOT / "runtime" / "custom-audit.jsonl"),
            "CHAT_API_RATE_LIMIT_ENABLED": "false",
            "CHAT_API_RATE_LIMIT_WINDOW_SECONDS": "7",
            "CHAT_API_RATE_LIMIT_REQUESTS": "8",
        }
        with patch.dict(os.environ, env, clear=True):
            settings = Settings.from_env()
        self.assertEqual(settings.host, "0.0.0.0")
        self.assertEqual(settings.port, 9999)
        self.assertEqual(settings.api_key, "secret")
        self.assertEqual(settings.workspace_root, PACKAGE_ROOT)
        self.assertTrue(settings.allow_any_cwd)
        self.assertEqual(settings.default_provider, "codex")
        self.assertEqual(settings.fallback_providers, ("codex", "claude"))
        self.assertFalse(settings.provider_fallback_enabled)
        self.assertEqual(settings.default_timeout_seconds, 12)
        self.assertEqual(settings.max_timeout_seconds, 34)
        self.assertEqual(settings.max_prompt_chars, 56)
        self.assertEqual(settings.codex_bin, "/tmp/codex-test")
        self.assertEqual(settings.claude_bin, "/tmp/claude-test")
        self.assertTrue(settings.allow_dangerous_sandboxes)
        self.assertEqual(settings.resolved_session_store_path(), PACKAGE_ROOT / "runtime" / "custom-sessions.json")
        self.assertEqual(settings.resolved_audit_log_path(), PACKAGE_ROOT / "runtime" / "custom-audit.jsonl")
        self.assertFalse(settings.rate_limit_enabled)
        self.assertEqual(settings.rate_limit_window_seconds, 7)
        self.assertEqual(settings.rate_limit_requests, 8)

    def test_env_bool_and_int_fallbacks(self) -> None:
        with patch.dict(os.environ, {"FLAG": "yes", "BROKEN": "nope"}, clear=True):
            self.assertTrue(_env_bool("FLAG"))
            self.assertFalse(_env_bool("MISSING"))
            self.assertEqual(_env_int("BROKEN", 44), 44)
            self.assertEqual(_env_int("MISSING", 55), 55)

    def test_provider_paths_report_missing_absolute_binary(self) -> None:
        settings = Settings(workspace_root=PACKAGE_ROOT, codex_bin="/missing/codex", claude_bin="/missing/claude")
        self.assertEqual(settings.provider_paths(), {"codex": None, "claude": None})

    def test_provider_paths_report_existing_absolute_binary(self) -> None:
        settings = Settings(workspace_root=PACKAGE_ROOT, codex_bin=str(Path(__file__)), claude_bin=str(Path(__file__)))
        paths = settings.provider_paths()
        self.assertEqual(paths["codex"], str(Path(__file__)))
        self.assertEqual(paths["claude"], str(Path(__file__)))


if __name__ == "__main__":
    unittest.main()
