from __future__ import annotations

import io
from contextlib import redirect_stdout
import unittest
from unittest.mock import patch

from primordial import cli


class _DummyRuntime:
    def __init__(self) -> None:
        self.initialized = False
        self.shutdown_called = False

    def initialize(self) -> None:
        self.initialized = True

    def shutdown(self) -> None:
        self.shutdown_called = True


class _DummyResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def read(self) -> bytes:
        return b'{"ok": true}'


class CliWebAliasTests(unittest.TestCase):
    def test_gui_command_launches_web_console(self) -> None:
        runtime = _DummyRuntime()
        with patch("primordial.cli.run_startup_preflight"), patch(
            "primordial.cli.PrimordialRuntime.from_env", return_value=runtime
        ), patch("primordial.cli.serve_web_console") as serve:
            result = cli.main(["gui", "--host", "0.0.0.0", "--port", "1444"])

        self.assertEqual(result, 0)
        self.assertTrue(runtime.initialized)
        self.assertTrue(runtime.shutdown_called)
        serve.assert_called_once_with(runtime, host="0.0.0.0", port=1444)

    def test_doctor_command_runs_without_runtime_startup(self) -> None:
        with patch("primordial.cli.run_doctor", return_value={"ok": True, "status": "ok", "checks": []}), patch(
            "primordial.cli.PrimordialRuntime.from_env"
        ) as from_env, redirect_stdout(io.StringIO()):
            result = cli.main(["doctor"])

        self.assertEqual(result, 0)
        from_env.assert_not_called()

    def test_stop_server_command_runs_without_runtime_startup(self) -> None:
        with patch("primordial.cli.urlrequest.urlopen", return_value=_DummyResponse()) as urlopen, patch(
            "primordial.cli.PrimordialRuntime.from_env"
        ) as from_env, redirect_stdout(io.StringIO()):
            result = cli.main(["stop-server", "--host", "127.0.0.1", "--port", "17777"])

        self.assertEqual(result, 0)
        from_env.assert_not_called()
        self.assertIn("/api/server/stop", urlopen.call_args.args[0].full_url)
