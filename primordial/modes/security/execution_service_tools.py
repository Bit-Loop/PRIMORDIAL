from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveServiceToolMixin:
    def _service_discovery_hosts(self, assets) -> list[dict[str, str]]:
        hosts: list[dict[str, str]] = []
        seen: set[str] = set()
        for asset in assets:
            host = ""
            if asset.asset_type == "webapp" or asset.asset.startswith(("http://", "https://")):
                host = parse.urlsplit(asset.asset).hostname or ""
            elif asset.asset_type in {"hostname", "ip"}:
                host = asset.asset.strip()
            if not host or host in seen:
                continue
            seen.add(host)
            hosts.append({"host": host, "asset_type": asset.asset_type, "source_asset": asset.asset})
        return hosts

    def _service_discovery_ports(self, metadata: dict[str, object]) -> list[int]:
        raw_ports = metadata.get("service_discovery_ports")
        if isinstance(raw_ports, list):
            parsed: list[int] = []
            for item in raw_ports:
                try:
                    port = int(item)
                except (TypeError, ValueError):
                    continue
                if 1 <= port <= 65535 and port not in parsed:
                    parsed.append(port)
            if parsed:
                return parsed[:128]
        return list(SERVICE_DISCOVERY_PORTS)

    def _scan_tcp_services(
        self,
        hosts: list[dict[str, str]],
        ports: list[int],
        timeout_seconds: int = 90,
    ) -> dict[str, object]:
        host_tool_scan = self._scan_tcp_services_with_host_tools(hosts, ports, timeout_seconds=timeout_seconds)
        if host_tool_scan is not None:
            return host_tool_scan
        return self._scan_tcp_services_with_sockets(hosts, ports)

    def _scan_tcp_services_with_sockets(self, hosts: list[dict[str, str]], ports: list[int]) -> dict[str, object]:
        open_services: list[dict[str, object]] = []
        errors: list[dict[str, object]] = []
        attempted = 0
        for host_entry in hosts:
            host = host_entry["host"]
            for port in ports:
                attempted += 1
                try:
                    with socket.create_connection((host, port), timeout=0.7) as sock:
                        banner = self._read_service_banner(sock, port)
                    open_services.append(
                        {
                            "host": host,
                            "port": port,
                            "service": self._guess_service(port, banner),
                            "banner": banner,
                            "source_asset": host_entry["source_asset"],
                        }
                    )
                except (ConnectionRefusedError, TimeoutError, socket.timeout):
                    continue
                except OSError as exc:
                    if len(errors) < 20:
                        errors.append({"host": host, "port": port, "error": str(exc)})
                    continue
        return {
            "open_services": open_services,
            "closed_count": max(0, attempted - len(open_services)),
            "errors": errors,
            "scanner": "python-socket",
            "command_results": [],
        }

    def _scan_tcp_services_with_host_tools(
        self,
        hosts: list[dict[str, str]],
        ports: list[int],
        timeout_seconds: int = 90,
    ) -> dict[str, object] | None:
        if shutil.which("rustscan") is None and shutil.which("nmap") is None:
            return None
        open_services: list[dict[str, object]] = []
        errors: list[dict[str, object]] = []
        command_results: list[dict[str, object]] = []
        attempted = len(hosts) * len(ports)
        for host_entry in hosts:
            host = host_entry["host"]
            host_ports = ports
            if shutil.which("rustscan") is not None:
                rustscan_result = self._run_rustscan_ports(host, ports, timeout_seconds=min(45, timeout_seconds))
                command_results.append(rustscan_result)
                discovered_ports = self._parse_rustscan_ports(str(rustscan_result.get("stdout", "")))
                if discovered_ports:
                    host_ports = discovered_ports
            if shutil.which("nmap") is not None:
                nmap_result = self._run_nmap_service_scan(host, host_ports, timeout_seconds=timeout_seconds)
                command_results.append(nmap_result)
                parsed = self._parse_nmap_xml_services(str(nmap_result.get("stdout", "")), host_entry)
                if parsed:
                    open_services.extend(parsed)
                    continue
                if nmap_result.get("executed") and nmap_result.get("returncode") not in {0, None}:
                    errors.append({"host": host, "tool": "nmap", "error": str(nmap_result.get("stderr", ""))[:400]})
            if shutil.which("rustscan") is not None and shutil.which("nmap") is None:
                for port in self._parse_rustscan_ports(str(command_results[-1].get("stdout", ""))):
                    open_services.append(
                        {
                            "host": host,
                            "port": port,
                            "service": SERVICE_NAME_BY_PORT.get(port, "unknown"),
                            "banner": "",
                            "source_asset": host_entry["source_asset"],
                            "scanner": "rustscan",
                        }
                    )
        if not command_results:
            return None
        return {
            "open_services": self._dedupe_open_services(open_services),
            "closed_count": max(0, attempted - len(open_services)),
            "errors": errors,
            "scanner": "rustscan+nmap" if shutil.which("rustscan") and shutil.which("nmap") else "nmap",
            "command_results": command_results,
        }

    def _run_rustscan_ports(self, host: str, ports: list[int], timeout_seconds: int = 45) -> dict[str, object]:
        return self._run_host_command(
            tool="rustscan",
            argv=[
                "rustscan",
                "-a",
                host,
                "-p",
                ",".join(str(port) for port in ports),
                "--ulimit",
                "5000",
                "--timeout",
                "1500",
                "--batch-size",
                "256",
            ],
            timeout_seconds=timeout_seconds,
        )

    def _run_nmap_service_scan(self, host: str, ports: list[int], timeout_seconds: int = 90) -> dict[str, object]:
        return self._run_host_command(
            tool="nmap",
            argv=[
                "nmap",
                "-Pn",
                "-sT",
                "-sV",
                "--version-light",
                "--max-retries",
                "2",
                "-p",
                ",".join(str(port) for port in ports),
                "-oX",
                "-",
                host,
            ],
            timeout_seconds=timeout_seconds,
        )

    def _parse_rustscan_ports(self, stdout: str) -> list[int]:
        ports: list[int] = []
        for match in re.finditer(r"Open\s+[^\s:]+:(\d+)", stdout, re.IGNORECASE):
            port = int(match.group(1))
            if port not in ports:
                ports.append(port)
        return ports

    def _parse_nmap_xml_services(self, stdout: str, host_entry: dict[str, str]) -> list[dict[str, object]]:
        xml_start = stdout.find("<?xml")
        if xml_start > 0:
            stdout = stdout[xml_start:]
        if not stdout.strip():
            return []
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            return []
        services: list[dict[str, object]] = []
        host = host_entry["host"]
        for port_node in root.findall(".//port"):
            state = port_node.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            try:
                port = int(port_node.attrib.get("portid", "0"))
            except ValueError:
                continue
            service_node = port_node.find("service")
            service_name = service_node.attrib.get("name", SERVICE_NAME_BY_PORT.get(port, "unknown")) if service_node is not None else SERVICE_NAME_BY_PORT.get(port, "unknown")
            banner_parts = []
            if service_node is not None:
                for key in ("product", "version", "extrainfo"):
                    value = service_node.attrib.get(key, "")
                    if value:
                        banner_parts.append(value)
            services.append(
                {
                    "host": host,
                    "port": port,
                    "service": service_name,
                    "banner": " ".join(banner_parts),
                    "source_asset": host_entry["source_asset"],
                    "scanner": "nmap",
                }
            )
        return services

    def _dedupe_open_services(self, services: list[dict[str, object]]) -> list[dict[str, object]]:
        deduped: dict[tuple[str, int], dict[str, object]] = {}
        for service in services:
            key = (str(service.get("host", "")), int(service.get("port", 0) or 0))
            deduped[key] = service
        return sorted(deduped.values(), key=lambda item: (str(item.get("host", "")), int(item.get("port", 0) or 0)))

    def _read_service_banner(self, sock: socket.socket, port: int) -> str:
        sock.settimeout(0.6)
        if port in {80, 5000, 5985, 8000, 8080, 8888, 10000}:
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\nUser-Agent: Primordial/0.1\r\n\r\n")
            except OSError:
                pass
        try:
            return self._sanitize_banner(sock.recv(160))
        except (OSError, TimeoutError):
            return ""

    def _sanitize_banner(self, banner: bytes) -> str:
        if not banner:
            return ""
        decoded = banner.decode("latin-1", errors="replace")
        compact = " ".join(decoded.replace("\x00", " ").split())
        return compact[:240]

    def _guess_service(self, port: int, banner: str) -> str:
        lowered = banner.lower()
        if banner.startswith("SSH-"):
            return "ssh"
        if lowered.startswith("http/") or "server:" in lowered:
            return "http"
        if "ftp" in lowered:
            return "ftp"
        if "smtp" in lowered:
            return "smtp"
        return SERVICE_NAME_BY_PORT.get(port, "unknown")

    def _summarize_open_services(
        self,
        open_services: list[dict[str, object]],
        *,
        host_count: int,
        port_count: int,
    ) -> str:
        if not open_services:
            return (
                f"TCP connect checks completed against {host_count} host(s) and {port_count} port(s); "
                "no open services were observed in the bounded port set."
            )
        summarized = ", ".join(
            f"{service['host']}:{service['port']}/{service['service']}"
            for service in open_services[:16]
        )
        suffix = "" if len(open_services) <= 16 else f" and {len(open_services) - 16} more"
        return f"TCP service discovery observed {len(open_services)} open service(s): {summarized}{suffix}."

    def _build_service_inventory_note(
        self,
        open_services: list[dict[str, object]],
        closed_count: int,
        errors: list[dict[str, object]],
    ) -> str:
        lines = [
            f"Open services: {len(open_services)}",
            f"Closed or filtered checks: {closed_count}",
            f"Scan errors retained: {len(errors)}",
        ]
        for service in open_services[:self.config.max_evidence_items]:
            banner = f" banner={service['banner']!r}" if service.get("banner") else ""
            lines.append(f"- {service['host']}:{service['port']} -> {service['service']}{banner}")
        if not open_services:
            lines.append("No open services were observed in the configured bounded port set.")
        lines.append("This is service inventory only, not an exploitation or vulnerability claim.")
        return "\n".join(lines)

    def _safe_artifact_fragment(self, value: str) -> str:
        return "".join(character if character.isalnum() else "_" for character in value).strip("_") or "target"
