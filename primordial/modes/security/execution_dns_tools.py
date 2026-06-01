from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveDnsToolMixin:
    def _run_dns_enumeration_commands(self, dns_server: str, domain: str) -> list[dict[str, object]]:
        queries = [
            ("soa", ["dig", f"@{dns_server}", domain, "SOA", "+time=5", "+tries=1"]),
            ("ns", ["dig", f"@{dns_server}", domain, "NS", "+time=5", "+tries=1"]),
            ("axfr", ["dig", f"@{dns_server}", domain, "AXFR", "+time=5", "+tries=1"]),
            (
                "ldap_srv",
                ["dig", f"@{dns_server}", f"_ldap._tcp.dc._msdcs.{domain}", "SRV", "+time=5", "+tries=1"],
            ),
            ("kerberos_srv", ["dig", f"@{dns_server}", f"_kerberos._tcp.{domain}", "SRV", "+time=5", "+tries=1"]),
            ("dc01_a", ["dig", f"@{dns_server}", f"DC01.{domain}", "A", "+time=5", "+tries=1"]),
        ]
        results: list[dict[str, object]] = []
        for name, argv in queries:
            result = self._run_host_command(tool=f"dig:{name}", argv=argv, timeout_seconds=8)
            result["query_name"] = name
            results.append(result)
        return results

    def _extract_dc_hostnames_from_srv(self, records: list[dict[str, str]], domain: str) -> list[str]:
        """Return DC hostnames found in LDAP/Kerberos SRV records.

        SRV value format: '<priority> <weight> <port> <target-hostname>'.
        Extracts the target and qualifies bare names against the domain.
        """
        hostnames: list[str] = []
        for record in records:
            if record.get("type") != "SRV":
                continue
            name = record.get("name", "").lower()
            if "_ldap._tcp" not in name and "_kerberos._tcp" not in name:
                continue
            parts = record.get("value", "").split()
            if len(parts) >= 4:
                host = parts[3].rstrip(".")
                if host and host not in hostnames:
                    hostnames.append(host if "." in host else f"{host}.{domain}")
        return hostnames

    def _parse_dns_enumeration(self, command_results: list[dict[str, object]]) -> dict[str, object]:
        records: dict[tuple[str, str, str], dict[str, str]] = {}
        zone_transfer_success = False
        for result in command_results:
            stdout = str(result.get("stdout", ""))
            query_name = str(result.get("query_name", ""))
            if query_name == "axfr" and "Transfer failed." not in stdout and "\tIN\tSOA\t" in stdout:
                zone_transfer_success = True
            for raw_line in stdout.splitlines():
                line = raw_line.strip()
                if not line or line.startswith(";") or "\tIN\t" not in line:
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                name = parts[0].rstrip(".")
                record_type = parts[3]
                value = " ".join(part.rstrip(".") for part in parts[4:])
                key = (name, record_type, value)
                records[key] = {"name": name, "type": record_type, "value": value, "source_query": query_name}
        return {
            "records": sorted(records.values(), key=lambda item: (item["name"], item["type"], item["value"])),
            "zone_transfer_success": zone_transfer_success,
        }

    def _summarize_dns_enumeration(self, dns_server: str, domain: str, parsed: dict[str, object]) -> str:
        records = parsed["records"]
        zone_status = "succeeded" if parsed["zone_transfer_success"] else "did not succeed"
        return (
            f"DNS enumeration queried {domain} via {dns_server}; parsed {len(records)} record(s). "
            f"AXFR {zone_status}."
        )

    def _build_dns_enumeration_note(
        self,
        dns_server: str,
        domain: str,
        parsed: dict[str, object],
        command_results: list[dict[str, object]],
    ) -> str:
        records = parsed["records"]
        executed = [
            f"{item['tool']} rc={item['returncode']} timeout={item['timeout']}"
            for item in command_results
            if item.get("executed")
        ]
        lines = [
            f"DNS server: {dns_server}",
            f"Domain: {domain}",
            f"Commands: {', '.join(executed) or 'none executed'}",
            f"AXFR success: {parsed['zone_transfer_success']}",
            f"Records parsed: {len(records)}",
        ]
        for record in records[:self.config.max_evidence_items]:
            lines.append(f"- {record['name']} {record['type']} {record['value']}")
        lines.append("This is DNS inventory only; no exploit or credentialed action was performed.")
        return "\n".join(lines)

    def _preferred_network_host(self, assets) -> str:
        ip_assets = [asset.asset for asset in assets if asset.asset_type == "ip"]
        if ip_assets:
            return ip_assets[0]
        hostname_assets = [asset.asset for asset in assets if asset.asset_type == "hostname"]
        if hostname_assets:
            return hostname_assets[0]
        for asset in assets:
            if asset.asset_type == "webapp" or asset.asset.startswith(("http://", "https://")):
                host = parse.urlsplit(asset.asset).hostname
                if host:
                    return host
        return ""
