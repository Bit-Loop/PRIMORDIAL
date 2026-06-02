from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveKerberosAttackToolMixin:
    def _run_kerberos_attack_check_commands(
        self,
        task: Task,
        target_id: str,
        host: str,
        domain: str,
        users: list[dict[str, object]],
        requested_checks: set[str],
    ) -> list[dict[str, object]]:
        command_results: list[dict[str, object]] = []
        if "kerberoast" in requested_checks:
            command_results.append(
                {
                    "tool": "kerberoast-spn-candidate-review",
                    "argv": ["spn-candidate-review"],
                    "executed": False,
                    "returncode": None,
                    "stdout": "SPN candidates retained from prior discovery; no TGS request or hash cracking was performed.",
                    "stderr": "",
                    "timeout": False,
                }
            )
        if "asrep_roast" not in requested_checks:
            return command_results
        tool = shutil.which("impacket-GetNPUsers") or shutil.which("GetNPUsers.py")
        if not tool:
            command_results.append(
                {
                    "tool": "GetNPUsers.py",
                    "argv": ["GetNPUsers.py"],
                    "executed": False,
                    "returncode": None,
                    "stdout": "",
                    "stderr": "tool not found",
                    "timeout": False,
                }
            )
            return command_results
        usernames = [str(user.get("username", "")).strip() for user in users if str(user.get("username", "")).strip()]
        usernames = [name for name in usernames if not name.endswith("$")][:80]
        user_file = self._write_task_text_file(task, target_id, "kerberos-users", "\n".join(usernames) + "\n")
        command_results.append(
            self._run_host_command(
                tool="GetNPUsers.py",
                argv=[
                    tool,
                    f"{domain}/",
                    "-dc-ip",
                    host,
                    "-usersfile",
                    user_file,
                    "-no-pass",
                ],
                timeout_seconds=90,
            )
        )
        return command_results

    def _write_task_text_file(self, task: Task, target_id: str, prefix: str, content: str) -> str:
        task_dir = self.config.artifacts_dir / (task.id or "task")
        task_dir.mkdir(parents=True, exist_ok=True)
        path = task_dir / f"{prefix}-{self._safe_artifact_fragment(target_id)}.txt"
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
        return str(path)

    def _parse_asrep_hashes(self, command_results: list[dict[str, object]]) -> list[dict[str, object]]:
        hashes: list[dict[str, object]] = []
        for result in command_results:
            stdout = str(result.get("stdout", ""))
            for raw_line in stdout.splitlines():
                line = raw_line.strip()
                if "$krb5asrep$" not in line.lower():
                    continue
                username = line.split(":", 1)[0].strip() if ":" in line else ""
                hashes.append(
                    {
                        "username": username,
                        "hash_sha256": hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest(),
                        "hash_present": True,
                        "raw_hash_stored": False,
                    }
                )
        return hashes

    def _redact_kerberos_attack_command_results(self, command_results: list[dict[str, object]]) -> list[dict[str, object]]:
        redacted = []
        for result in command_results:
            stored = dict(result)
            stored["stdout"] = self._redact_asrep_hash_lines(str(stored.get("stdout") or ""))
            stored["stderr"] = self._redact_asrep_hash_lines(str(stored.get("stderr") or ""))
            redacted.append(stored)
        return redacted

    def _redact_asrep_hash_lines(self, value: str) -> str:
        lines = []
        for raw_line in value.splitlines():
            line = raw_line.strip()
            if "$krb5asrep$" not in line.lower():
                lines.append(raw_line)
                continue
            username = line.split(":", 1)[0].strip() if ":" in line else ""
            prefix = f"{username}: " if username else ""
            lines.append(f"{prefix}<redacted-asrep-hash>")
        return "\n".join(lines)

    def _summarize_kerberos_attack_check(
        self,
        asrep_hashes: list[dict[str, object]],
        spn_candidates: list[dict[str, str]],
        command_results: list[dict[str, object]],
    ) -> str:
        executed = [item["tool"] for item in command_results if item.get("executed")]
        return (
            f"Kerberos checks ran {', '.join(executed) or 'no host tools'} and found "
            f"{len(asrep_hashes)} AS-REP hash candidate(s) plus {len(spn_candidates)} SPN candidate(s). "
            "No hash cracking or PoC execution was performed."
        )

    def _build_kerberos_attack_check_note(
        self,
        domain: str,
        users: list[dict[str, object]],
        asrep_hashes: list[dict[str, object]],
        spn_candidates: list[dict[str, str]],
        command_results: list[dict[str, object]],
    ) -> str:
        lines = [
            f"Domain: {domain}",
            f"Users checked: {len(users)}",
            f"AS-REP hash candidates: {len(asrep_hashes)}",
            f"SPN candidates retained: {len(spn_candidates)}",
            "Hash cracking was not performed.",
        ]
        for result in command_results:
            lines.append(f"- {result['tool']} executed={result['executed']} rc={result['returncode']} timeout={result['timeout']}")
        for item in asrep_hashes[:self.config.max_evidence_items]:
            lines.append(f"- AS-REP candidate {item.get('username') or 'unknown'}")
        for item in spn_candidates[:self.config.max_evidence_items]:
            lines.append(f"- SPN candidate {item['username']}: {item['spn']}")
        return "\n".join(lines)
