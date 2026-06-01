from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveCommandToolMixin:
    def _run_ad_enumeration_commands(self, host: str) -> list[dict[str, object]]:
        commands = [
            {
                "tool": "ldapsearch",
                "argv": [
                    "ldapsearch",
                    "-x",
                    "-H",
                    f"ldap://{host}",
                    "-s",
                    "base",
                    "-b",
                    "",
                    "namingContexts",
                    "defaultNamingContext",
                    "rootDomainNamingContext",
                    "dnsHostName",
                    "supportedSASLMechanisms",
                ],
                "timeout": 15,
            },
            {
                "tool": "smbclient",
                "argv": ["smbclient", "-L", f"//{host}/", "-N", "-g", "-m", "SMB3"],
                "timeout": 18,
            },
            {
                "tool": "rpcclient",
                "argv": [
                    "rpcclient",
                    "-U",
                    "",
                    "-N",
                    host,
                    "-c",
                    "srvinfo;querydominfo;enumdomusers;enumdomgroups",
                ],
                "timeout": 25,
            },
            {
                "tool": "netexec",
                "argv": [
                    next((t for t in ["netexec", "nxc", "crackmapexec", "cme"] if shutil.which(t)), "netexec"),
                    "smb", host, "-u", "", "-p", "", "--shares",
                ],
                "timeout": 30,
            },
        ]
        results: list[dict[str, object]] = []
        for command in commands:
            results.append(
                self._run_host_command(
                    tool=str(command["tool"]),
                    argv=[str(item) for item in command["argv"]],
                    timeout_seconds=int(command["timeout"]),
                )
            )
        return results

    def _run_host_command(self, *, tool: str, argv: list[str], timeout_seconds: int) -> dict[str, object]:
        if shutil.which(argv[0]) is None:
            return {
                "tool": tool,
                "argv": argv,
                "executed": False,
                "returncode": None,
                "stdout": "",
                "stderr": "tool not found",
                "timeout": False,
            }
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            return {
                "tool": tool,
                "argv": argv,
                "executed": True,
                "returncode": completed.returncode,
                "stdout": self._truncate_command_output(completed.stdout),
                "stderr": self._truncate_command_output(completed.stderr),
                "timeout": False,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "tool": tool,
                "argv": argv,
                "executed": True,
                "returncode": None,
                "stdout": self._truncate_command_output(exc.stdout or ""),
                "stderr": self._truncate_command_output(exc.stderr or "command timed out"),
                "timeout": True,
            }

    def _run_secret_host_command(
        self,
        *,
        tool: str,
        argv: list[str],
        redacted_argv: list[str],
        timeout_seconds: int,
    ) -> dict[str, object]:
        if shutil.which(argv[0]) is None:
            return {
                "tool": tool,
                "argv": redacted_argv,
                "executed": False,
                "returncode": None,
                "stdout": "",
                "stderr": "tool not found",
                "timeout": False,
            }
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            return {
                "tool": tool,
                "argv": redacted_argv,
                "executed": True,
                "returncode": completed.returncode,
                "stdout": self._truncate_command_output(completed.stdout),
                "stderr": self._truncate_command_output(completed.stderr),
                "timeout": False,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "tool": tool,
                "argv": redacted_argv,
                "executed": True,
                "returncode": None,
                "stdout": self._truncate_command_output(exc.stdout or ""),
                "stderr": self._truncate_command_output(exc.stderr or "command timed out"),
                "timeout": True,
            }

    def _truncate_command_output(self, value: object, limit: int = 12000) -> str:
        if isinstance(value, bytes):
            rendered = value.decode("utf-8", errors="replace")
        else:
            rendered = str(value or "")
        return rendered if len(rendered) <= limit else rendered[:limit] + "\n...TRUNCATED..."
