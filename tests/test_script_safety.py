from __future__ import annotations

import unittest

from primordial.core.autonomy.safety import ScriptSafetyValidator


class ScriptSafetyValidatorTests(unittest.TestCase):
    def test_rejects_dangerous_import_alias_calls(self) -> None:
        validator = ScriptSafetyValidator()

        cases = {
            "os_system_alias": "from os import system\nsystem('id')\n",
            "importlib_alias": "from importlib import import_module\nimport_module('subprocess')\n",
            "subprocess_run_alias": "from subprocess import run\nrun(['id'])\n",
            "socket_alias": "from socket import socket\nsocket()\n",
        }

        for name, source in cases.items():
            with self.subTest(name=name):
                ok, issues = validator.validate(source)

                self.assertFalse(ok)
                self.assertTrue(issues)


if __name__ == "__main__":
    unittest.main()
