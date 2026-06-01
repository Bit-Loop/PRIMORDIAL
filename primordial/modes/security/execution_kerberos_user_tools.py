from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveKerberosUserToolMixin:
    def _kerberos_domain(self, target_id: str, handle: str) -> str:
        for evidence in self.store.list_evidence(target_id=target_id, limit=200):
            if evidence.metadata.get("kind") == "kerberos_user_discovery":
                domain = str(evidence.metadata.get("domain", "")).strip()
                if domain:
                    return domain
        return self._domain_from_base_dn(self._default_naming_context(target_id)) or self._domain_from_target(handle)

    def _run_kerberos_user_discovery_commands(self, host: str, base_dn: str) -> list[dict[str, object]]:
        commands = []
        if base_dn:
            commands.append(
                {
                    "tool": "ldapsearch",
                    "argv": [
                        "ldapsearch",
                        "-x",
                        "-LLL",
                        "-H",
                        f"ldap://{host}",
                        "-b",
                        base_dn,
                        "(|(objectClass=user)(objectClass=person))",
                        "sAMAccountName",
                        "userPrincipalName",
                        "servicePrincipalName",
                        "userAccountControl",
                    ],
                    "timeout": 30,
                }
            )
        commands.extend(
            [
                {
                    "tool": "rpcclient",
                    "argv": ["rpcclient", "-U", "", "-N", host, "-c", "enumdomusers"],
                    "timeout": 20,
                },
                {
                    "tool": "netexec",
                    "argv": ["netexec", "smb", host, "-u", "", "-p", "", "--users"],
                    "timeout": 35,
                },
            ]
        )
        return [
            self._run_host_command(
                tool=str(command["tool"]),
                argv=[str(item) for item in command["argv"]],
                timeout_seconds=int(command["timeout"]),
            )
            for command in commands
        ]

    def _parse_kerberos_user_discovery(
        self,
        command_results: list[dict[str, object]],
        domain: str,
    ) -> dict[str, object]:
        users: dict[str, dict[str, object]] = {}
        spn_candidates: list[dict[str, str]] = []
        for result in command_results:
            tool = str(result.get("tool", ""))
            stdout = str(result.get("stdout", ""))
            if tool == "ldapsearch":
                for record in self._parse_ldap_user_records(stdout, domain):
                    name = str(record.get("username", ""))
                    if not name or name.endswith("$"):
                        continue
                    users.setdefault(name.lower(), record)
                    for spn in record.get("servicePrincipalName", []):
                        spn_candidates.append({"username": name, "spn": str(spn)})
            elif tool == "rpcclient":
                for user in self._parse_rpc_users(stdout):
                    name = user["name"]
                    if not name or name.endswith("$"):
                        continue
                    users.setdefault(name.lower(), {"username": name, "source": "rpcclient", "rid": user["rid"]})
            elif tool == "netexec":
                for name in self._parse_netexec_users(stdout):
                    if not name or name.endswith("$"):
                        continue
                    users.setdefault(name.lower(), {"username": name, "source": "netexec"})
        return {
            "users": sorted(users.values(), key=lambda item: str(item.get("username", "")).lower()),
            "spn_candidates": sorted(spn_candidates, key=lambda item: (item["username"].lower(), item["spn"].lower())),
        }

    def _parse_ldap_user_records(self, stdout: str, domain: str) -> list[dict[str, object]]:
        records: list[dict[str, object]] = []
        current: dict[str, list[str]] = {}
        for raw_line in stdout.splitlines() + [""]:
            line = raw_line.strip()
            if not line:
                if current:
                    username = (current.get("sAMAccountName") or [""])[0]
                    if username:
                        records.append(
                            {
                                "username": username,
                                "upn": (current.get("userPrincipalName") or [f"{username}@{domain}"])[0],
                                "servicePrincipalName": current.get("servicePrincipalName", []),
                                "userAccountControl": (current.get("userAccountControl") or [""])[0],
                                "source": "ldapsearch",
                            }
                        )
                    current = {}
                continue
            if ": " not in line:
                continue
            key, value = line.split(": ", 1)
            current.setdefault(key, []).append(value)
        return records

    def _parse_netexec_users(self, stdout: str) -> list[str]:
        users: list[str] = []
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line or "[+]" in line or "[-]" in line:
                continue
            match = re.search(r"\b([A-Za-z0-9_.-]+)\s+(?:badpwdcount|description|pwdlastset|lastlogon)", line, re.IGNORECASE)
            if match and match.group(1) not in users:
                users.append(match.group(1))
        return users

    def _summarize_kerberos_user_discovery(self, host: str, parsed: dict[str, object]) -> str:
        users = parsed["users"]
        spns = parsed["spn_candidates"]
        return f"Kerberos user discovery against {host} found {len(users)} user principal(s) and {len(spns)} SPN candidate(s)."

    def _build_kerberos_user_discovery_note(
        self,
        host: str,
        domain: str,
        parsed: dict[str, object],
        command_results: list[dict[str, object]],
    ) -> str:
        users = parsed["users"]
        spns = parsed["spn_candidates"]
        executed = [f"{item['tool']} rc={item['returncode']} timeout={item['timeout']}" for item in command_results if item.get("executed")]
        lines = [
            f"Host: {host}",
            f"Domain: {domain or 'unknown'}",
            f"Commands: {', '.join(executed) or 'none executed'}",
            f"Users discovered: {len(users)}",
            f"SPN candidates: {len(spns)}",
        ]
        for user in users[:self.config.max_evidence_items]:
            lines.append(f"- user {user.get('username')} source={user.get('source')}")
        for spn in spns[:self.config.max_evidence_items]:
            lines.append(f"- spn {spn['username']}: {spn['spn']}")
        lines.append("No password spraying, cracking, or exploit execution was performed.")
        return "\n".join(lines)

    def _discovered_kerberos_users(self, target_id: str) -> list[dict[str, object]]:
        users: dict[str, dict[str, object]] = {}
        for evidence in self.store.list_evidence(target_id=target_id, limit=200):
            if evidence.metadata.get("kind") != "kerberos_user_discovery":
                continue
            for user in evidence.metadata.get("users", []):
                if not isinstance(user, dict):
                    continue
                username = str(user.get("username", "")).strip()
                if username:
                    users.setdefault(username.lower(), user)
        return sorted(users.values(), key=lambda item: str(item.get("username", "")).lower())

    def _discovered_spn_candidates(self, target_id: str) -> list[dict[str, str]]:
        spns: dict[tuple[str, str], dict[str, str]] = {}
        for evidence in self.store.list_evidence(target_id=target_id, limit=200):
            if evidence.metadata.get("kind") != "kerberos_user_discovery":
                continue
            for spn in evidence.metadata.get("spn_candidates", []):
                if not isinstance(spn, dict):
                    continue
                username = str(spn.get("username", "")).strip()
                value = str(spn.get("spn", "")).strip()
                if username and value:
                    spns.setdefault((username.lower(), value.lower()), {"username": username, "spn": value})
        return sorted(spns.values(), key=lambda item: (item["username"].lower(), item["spn"].lower()))
