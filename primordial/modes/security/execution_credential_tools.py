from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveCredentialToolMixin:
    def _run_credentialed_access_commands(
        self,
        task: Task,
        target_id: str,
        host: str,
        username: str,
        password: str,
        domain: str,
        *,
        protocols: set[str] | None = None,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
        auth_file = self._write_smb_auth_file(username, password, domain)
        command_results: list[dict[str, object]] = []
        auth_results: list[dict[str, object]] = []
        flag_hits: list[dict[str, object]] = []
        policy = self._active_intent_policy()
        flag_collection_allowed = bool(policy and policy.lab_policy.lab_flag_collection_allowed)
        protocols = protocols or {"smb", "winrm"}
        if "smb" in protocols:
            self._run_smb_credentialed_access(
                task,
                target_id,
                host,
                auth_file,
                username,
                command_results,
                auth_results,
                flag_hits,
                flag_collection_allowed=flag_collection_allowed,
            )
        else:
            command_results.append(self._disabled_smb_result(host))

        if "winrm" in protocols and os.getenv("PRIMORDIAL_ALLOW_PASSWORD_ARG_TOOLS", "").strip() == "1":
            self._run_winrm_credentialed_access(host, username, password, domain, command_results, auth_results)
        elif "winrm" in protocols:
            command_results.append(self._disabled_winrm_result(host, username))
        return command_results, auth_results, flag_hits

    def _run_smb_credentialed_access(
        self,
        task: Task,
        target_id: str,
        host: str,
        auth_file: str,
        username: str,
        command_results: list[dict[str, object]],
        auth_results: list[dict[str, object]],
        flag_hits: list[dict[str, object]],
        *,
        flag_collection_allowed: bool,
    ) -> None:
        smb_result = self._run_secret_host_command(
            tool="smbclient",
            argv=["smbclient", "-A", auth_file, "-L", f"//{host}/", "-g", "-m", "SMB3"],
            redacted_argv=["smbclient", "-A", "<credential-file>", "-L", f"//{host}/", "-g", "-m", "SMB3"],
            timeout_seconds=25,
        )
        command_results.append(smb_result)
        smb_returncode = smb_result.get("returncode")
        smb_valid = bool(smb_result.get("executed")) and smb_returncode is not None and int(smb_returncode) == 0
        auth_results.append({"protocol": "smb", "valid": smb_valid, "tool": "smbclient"})
        if smb_valid and flag_collection_allowed:
            flag_hits.extend(self._collect_smb_flags(task, target_id, host, auth_file, username))
        elif smb_valid:
            command_results.append(self._disabled_smb_flag_collection_result(host))

    def _run_winrm_credentialed_access(
        self,
        host: str,
        username: str,
        password: str,
        domain: str,
        command_results: list[dict[str, object]],
        auth_results: list[dict[str, object]],
    ) -> None:
        winrm_result = self._run_secret_host_command(
            tool="netexec",
            argv=["netexec", "winrm", host, "-u", username, "-p", password, *self._domain_args(domain)],
            redacted_argv=["netexec", "winrm", host, "-u", username, "-p", "<redacted>", *self._domain_args(domain)],
            timeout_seconds=35,
        )
        command_results.append(winrm_result)
        stdout = str(winrm_result.get("stdout", ""))
        winrm_rc = winrm_result.get("returncode")
        valid = bool(winrm_result.get("executed")) and winrm_rc is not None and (
            int(winrm_rc) == 0 or "[+]" in stdout or "pwn3d" in stdout.lower()
        )
        auth_results.append({"protocol": "winrm", "valid": valid, "tool": "netexec"})

    def _disabled_smb_result(self, host: str) -> dict[str, object]:
        return {
            "tool": "smbclient",
            "argv": ["smbclient", "-A", "<credential-file>", "-L", f"//{host}/"],
            "executed": False,
            "returncode": None,
            "stdout": "",
            "stderr": "disabled: current credentialed-access surface did not admit SMB",
            "timeout": False,
        }

    def _disabled_smb_flag_collection_result(self, host: str) -> dict[str, object]:
        return {
            "tool": "smbclient",
            "argv": ["smbclient", "-A", "<credential-file>", f"//{host}/C$", "-c", "<flag-collection>"],
            "executed": False,
            "returncode": None,
            "stdout": "",
            "stderr": "disabled: active operator intent does not allow lab flag collection",
            "timeout": False,
        }

    def _disabled_winrm_result(self, host: str, username: str) -> dict[str, object]:
        return {
            "tool": "netexec",
            "argv": ["netexec", "winrm", host, "-u", username, "-p", "<redacted>"],
            "executed": False,
            "returncode": None,
            "stdout": "",
            "stderr": "disabled: set PRIMORDIAL_ALLOW_PASSWORD_ARG_TOOLS=1 to allow password-in-argv WinRM tooling",
            "timeout": False,
        }

    def _credentialed_access_protocols(self, task: Task) -> set[str]:
        raw = task.metadata.get("protocols")
        if isinstance(raw, list):
            protocols = {str(item).strip().lower() for item in raw if str(item).strip()}
            protocols = protocols.intersection({"smb", "winrm"})
            if protocols:
                return protocols
        surface = task.metadata.get("credentialed_access_surface", {})
        if isinstance(surface, dict):
            raw_surface = surface.get("protocols")
            if isinstance(raw_surface, list):
                protocols = {str(item).strip().lower() for item in raw_surface if str(item).strip()}
                protocols = protocols.intersection({"smb", "winrm"})
                if protocols:
                    return protocols
        return {"smb", "winrm"}

    def _domain_args(self, domain: str) -> list[str]:
        return ["-d", domain] if domain else []

    def _write_smb_auth_file(self, username: str, password: str, domain: str) -> str:
        auth_dir = self.config.secrets_dir / "tool-auth"
        auth_dir.mkdir(parents=True, exist_ok=True)
        auth_dir.chmod(0o700)
        path = auth_dir / "smbclient.auth"
        lines = [f"username = {username}", f"password = {password}"]
        if domain:
            lines.append(f"domain = {domain}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        path.chmod(0o600)
        return str(path)

    def _smb_flag_candidates(
        self, target_id: str, username: str
    ) -> list[tuple[str, str, str]]:
        """Return (share, remote_path, flag_name) tuples.

        Operators can override via target.metadata["flag_paths"]: a list of
        {"share": "C$", "path": "Users\\...\\flag.txt", "name": "flag.txt"} dicts.
        Falls back to common in-house lab user.txt / root.txt paths.
        """
        target = self.store.get_target(target_id)
        custom = target.metadata.get("flag_paths") if target else None
        if isinstance(custom, list) and custom:
            result = []
            for entry in custom:
                if isinstance(entry, dict) and entry.get("path") and entry.get("name"):
                    result.append((
                        str(entry.get("share", "C$")),
                        str(entry["path"]),
                        str(entry["name"]),
                    ))
            if result:
                return result
        return [
            ("C$", f"Users\\{username}\\Desktop\\user.txt", "user.txt"),
            ("C$", "Users\\Administrator\\Desktop\\root.txt", "root.txt"),
        ]

    def _collect_smb_flags(
        self,
        task: Task,
        target_id: str,
        host: str,
        auth_file: str,
        username: str,
    ) -> list[dict[str, object]]:
        flag_hits: list[dict[str, object]] = []
        candidates = self._smb_flag_candidates(target_id, username)
        flag_dir = self.config.artifacts_dir / (task.id or "task") / "flags"
        flag_dir.mkdir(parents=True, exist_ok=True)
        flag_dir.chmod(0o700)
        for share, remote_path, flag_name in candidates:
            local_path = flag_dir / f"{self._safe_artifact_fragment(target_id)}-{flag_name}"
            command = f'get "{remote_path}" "{local_path}"'
            result = self._run_secret_host_command(
                tool="smbclient",
                argv=["smbclient", "-A", auth_file, f"//{host}/{share}", "-m", "SMB3", "-c", command],
                redacted_argv=["smbclient", "-A", "<credential-file>", f"//{host}/{share}", "-m", "SMB3", "-c", command],
                timeout_seconds=25,
            )
            if not local_path.exists():
                continue
            value = local_path.read_text(encoding="utf-8", errors="replace").strip()
            local_path.chmod(0o600)
            if not value:
                continue
            flag_hits.append(
                {
                    "source": "smb",
                    "share": share,
                    "remote_path": remote_path,
                    "flag_name": flag_name,
                    "content_collected": True,
                    "value": value,
                    "local_path": str(local_path),
                    "tool_returncode": result.get("returncode"),
                }
            )
        return flag_hits

    def _summarize_credentialed_access(
        self,
        auth_results: list[dict[str, object]],
        flag_hits: list[dict[str, object]],
    ) -> str:
        valid = [item["protocol"] for item in auth_results if item.get("valid")]
        summary = f"Credentialed access checks validated {', '.join(valid) if valid else 'no'} protocol access."
        if flag_hits:
            summary += f" Observed {len(flag_hits)} lab flag file candidate(s)."
        return summary

    def _build_credentialed_access_note(
        self,
        host: str,
        username: str,
        domain: str,
        auth_results: list[dict[str, object]],
        flag_hits: list[dict[str, object]],
        command_results: list[dict[str, object]],
    ) -> str:
        lines = [
            f"Host: {host}",
            f"Username: {username}",
            f"Domain: {domain or 'not configured'}",
            f"Auth checks: {len(auth_results)}",
        ]
        if flag_hits:
            lines.append(f"Lab flag file candidates observed: {len(flag_hits)}")
        for item in auth_results:
            lines.append(f"- {item['protocol']}: valid={item['valid']} tool={item['tool']}")
        for item in flag_hits:
            lines.append(f"- {item['flag_name']} observed via {item['source']} share={item.get('share')}")
        for result in command_results:
            lines.append(f"- {result['tool']} executed={result['executed']} rc={result['returncode']} timeout={result['timeout']}")
        lines.append("Passwords are redacted from artifacts. WinRM password-argv tools are disabled unless explicitly opted in.")
        return "\n".join(lines)
