from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveAdParsingMixin:
    def _parse_ad_enumeration(self, command_results: list[dict[str, object]]) -> dict[str, object]:
        by_tool = {str(item["tool"]): item for item in command_results}
        return {
            "ldap_rootdse": self._parse_ldap_rootdse(str(by_tool.get("ldapsearch", {}).get("stdout", ""))),
            "smb_shares": self._parse_smb_shares(
                str(by_tool.get("smbclient", {}).get("stdout", ""))
                + "\n"
                + str(by_tool.get("netexec", {}).get("stdout", ""))
            ),
            "rpc_users": self._parse_rpc_users(str(by_tool.get("rpcclient", {}).get("stdout", ""))),
            "rpc_groups": self._parse_rpc_groups(str(by_tool.get("rpcclient", {}).get("stdout", ""))),
        }

    def _parse_ldap_rootdse(self, stdout: str) -> dict[str, object]:
        values: dict[str, list[str]] = {}
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or ": " not in line:
                continue
            key, value = line.split(": ", 1)
            values.setdefault(key, []).append(value)
        return values

    def _parse_smb_shares(self, stdout: str) -> list[dict[str, str]]:
        shares: dict[str, dict[str, str]] = {}
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if "|" in line:
                parts = line.split("|")
                if len(parts) >= 2 and parts[0].lower() in {"disk", "ipc", "printer"}:
                    shares[parts[1]] = {
                        "name": parts[1],
                        "type": parts[0],
                        "comment": parts[2] if len(parts) > 2 else "",
                    }
            elif re.match(r"^(SMB|WINRM|LDAP|RPC)", line):
                tokens = line.split()
                for index, token in enumerate(tokens):
                    if token.upper() == "READ" and index > 0:
                        name = tokens[index - 1]
                        shares.setdefault(name, {"name": name, "type": "disk", "comment": "netexec readable"})
        return sorted(shares.values(), key=lambda item: item["name"].lower())

    def _parse_rpc_users(self, stdout: str) -> list[dict[str, str]]:
        users: list[dict[str, str]] = []
        seen: set[str] = set()
        for match in re.finditer(r"user:\[([^\]]+)\]\s+rid:\[([^\]]+)\]", stdout, re.IGNORECASE):
            username = match.group(1)
            if username in seen:
                continue
            seen.add(username)
            users.append({"name": username, "rid": match.group(2)})
        return users

    def _parse_rpc_groups(self, stdout: str) -> list[dict[str, str]]:
        groups: list[dict[str, str]] = []
        seen: set[str] = set()
        for match in re.finditer(r"group:\[([^\]]+)\]\s+rid:\[([^\]]+)\]", stdout, re.IGNORECASE):
            group = match.group(1)
            if group in seen:
                continue
            seen.add(group)
            groups.append({"name": group, "rid": match.group(2)})
        return groups

    def _summarize_ad_enumeration(self, host: str, parsed: dict[str, object]) -> str:
        rootdse = parsed["ldap_rootdse"]
        naming_contexts = []
        if isinstance(rootdse, dict):
            naming_contexts = list(rootdse.get("namingContexts", [])) + list(rootdse.get("defaultNamingContext", []))
        shares = parsed["smb_shares"]
        users = parsed["rpc_users"]
        return (
            f"Anonymous AD enumeration against {host} observed "
            f"{len(naming_contexts)} LDAP naming context value(s), "
            f"{len(shares)} SMB share candidate(s), and {len(users)} RPC user candidate(s)."
        )

    def _build_ad_enumeration_note(
        self,
        host: str,
        parsed: dict[str, object],
        command_results: list[dict[str, object]],
    ) -> str:
        rootdse = parsed["ldap_rootdse"]
        shares = parsed["smb_shares"]
        users = parsed["rpc_users"]
        groups = parsed["rpc_groups"]
        executed = [
            f"{item['tool']} rc={item['returncode']} timeout={item['timeout']}"
            for item in command_results
            if item.get("executed")
        ]
        lines = [
            f"Host: {host}",
            f"Commands: {', '.join(executed) or 'none executed'}",
            f"LDAP RootDSE keys: {', '.join(sorted(rootdse.keys())) if isinstance(rootdse, dict) else 'none'}",
            f"SMB shares parsed: {len(shares)}",
            f"RPC users parsed: {len(users)}",
            f"RPC groups parsed: {len(groups)}",
        ]
        for share in shares[:self.config.max_evidence_items]:
            lines.append(f"- share {share['name']} ({share.get('type', 'unknown')}): {share.get('comment', '')}")
        for user in users[:self.config.max_evidence_items]:
            lines.append(f"- user {user['name']} rid={user['rid']}")
        lines.append("This is anonymous inventory only; no credential use or exploit step was performed.")
        return "\n".join(lines)

    def _default_naming_context(self, target_id: str) -> str:
        for evidence in self.store.list_evidence(target_id=target_id, limit=200):
            rootdse = evidence.metadata.get("ldap_rootdse", {})
            if not isinstance(rootdse, dict):
                continue
            for key in ("defaultNamingContext", "rootDomainNamingContext", "namingContexts"):
                values = rootdse.get(key, [])
                if isinstance(values, list) and values:
                    return str(values[0])
                if isinstance(values, str) and values:
                    return values
        return ""

    def _domain_from_base_dn(self, base_dn: str) -> str:
        parts = []
        for component in base_dn.split(","):
            component = component.strip()
            if component.lower().startswith("dc="):
                parts.append(component.split("=", 1)[1])
        return ".".join(parts)

    def _domain_from_target(self, handle: str) -> str:
        return handle.strip().strip(".") if "." in handle else ""
