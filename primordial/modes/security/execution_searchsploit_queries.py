from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveSearchsploitQueryMixin:
    def _build_searchsploit_queries(self, target_id: str) -> list[str]:
        target = self.store.get_target(target_id)
        evidence = self._records_for_generation(
            self.store.list_evidence(target_id=target_id, limit=200),
            self._target_active_generation(target),
        )
        policy = self._active_intent_policy()
        allow_lab_fallbacks = bool(policy and policy.lab_policy.htb_lab_behavior_allowed)
        queries: list[str] = []
        fallbacks: list[str] = []

        def add(value: str, *, fallback: bool = False) -> None:
            normalized = self._normalize_searchsploit_query(value)
            if not normalized:
                return
            if fallback and self._is_redundant_searchsploit_fallback(normalized, queries):
                return
            destination = fallbacks if fallback else queries
            if normalized.lower() in {item.lower() for item in queries + fallbacks}:
                return
            destination.append(normalized)

        for item in evidence:
            headers = item.metadata.get("headers")
            if isinstance(headers, dict):
                server = str(headers.get("server", "")).strip()
                for query in self._queries_from_service_banner("http", server):
                    add(query)
            title = str(item.metadata.get("title", "")).strip()
            if title and "iis" in title.lower():
                add("Microsoft IIS", fallback=True)
            for service in item.metadata.get("open_services", []):
                if not isinstance(service, dict):
                    continue
                service_name = str(service.get("service", "")).strip()
                banner = str(service.get("banner", "")).strip()
                extracted = self._queries_from_service_banner(service_name, banner)
                for query in extracted:
                    add(query)
                if service_name in {"http", "https", "http-alt"} and not extracted:
                    add("Microsoft IIS", fallback=True)
                elif service_name in {"smb", "netbios-ssn"} and not extracted:
                    add("Windows SMB", fallback=True)
                elif service_name in {"ldap", "ldaps", "kerberos", "global-catalog"}:
                    add("Active Directory LDAP", fallback=True)
                elif service_name in {"winrm", "winrm-http", "winrm-https"}:
                    add("Microsoft WinRM", fallback=True)
        for item in evidence:
            rootdse = item.metadata.get("ldap_rootdse")
            if isinstance(rootdse, dict) and rootdse:
                add("Active Directory LDAP", fallback=True)
        fallbacks = [fallback for fallback in fallbacks if not self._is_redundant_searchsploit_fallback(fallback, queries)]
        selected = queries[:8]
        if allow_lab_fallbacks:
            for fallback in fallbacks:
                if len(selected) >= 10:
                    break
                if fallback.lower() not in {item.lower() for item in selected}:
                    selected.append(fallback)
        return selected

    def _is_redundant_searchsploit_fallback(self, fallback: str, precise_queries: list[str]) -> bool:
        lowered = fallback.lower()
        precise = " ".join(precise_queries).lower()
        if lowered in {"microsoft iis", "iis"} and re.search(r"\b(?:microsoft\s+)?iis\s+\d", precise):
            return True
        if lowered in {"windows smb", "microsoft windows smb", "smb"} and re.search(r"\bsmb\s+\d", precise):
            return True
        return False

    def _normalize_searchsploit_query(self, value: str) -> str | None:
        raw_lowered = " ".join(value.split()).strip().lower()
        if raw_lowered.startswith(EXPLOIT_RESEARCH_HTTP_TRASH_PREFIXES):
            return None
        normalized = " ".join(value.replace("/", " ").replace("_", " ").split()).strip(" -:;,")
        if len(normalized) < 3:
            return None
        if any(prefix in raw_lowered for prefix in ("content-length:", "content-type:", "last-modified:", "etag:")):
            return None
        if len(normalized) > 80:
            return None
        return normalized

    def _queries_from_service_banner(self, service_name: str, banner: str) -> list[str]:
        normalized_banner = " ".join(banner.split()).strip()
        if not normalized_banner:
            return []
        if normalized_banner.lower().startswith("http/1."):
            server = self._server_from_http_banner(normalized_banner)
            if server:
                normalized_banner = server
        queries: list[str] = []

        def add(value: str) -> None:
            normalized = self._normalize_searchsploit_query(value)
            if normalized and normalized.lower() not in {item.lower() for item in queries}:
                queries.append(normalized)

        for match in re.finditer(r"Microsoft-IIS/([0-9]+(?:\.[0-9]+)*)", normalized_banner, flags=re.IGNORECASE):
            version = match.group(1)
            add(f"Microsoft IIS {version}")
            add(f"IIS {version}")
        for match in re.finditer(r"OpenSSH[_ -]?([0-9]+(?:\.[0-9]+)*)", normalized_banner, flags=re.IGNORECASE):
            add(f"OpenSSH {match.group(1)}")
        for match in re.finditer(r"Apache(?: httpd)?[/ ]([0-9]+(?:\.[0-9]+)*)", normalized_banner, flags=re.IGNORECASE):
            add(f"Apache {match.group(1)}")
        for match in re.finditer(r"nginx[/ ]([0-9]+(?:\.[0-9]+)*)", normalized_banner, flags=re.IGNORECASE):
            add(f"nginx {match.group(1)}")
        if service_name in {"smb", "netbios-ssn"}:
            for match in re.finditer(r"SMBv?([0-9]+(?:\.[0-9]+)*)", normalized_banner, flags=re.IGNORECASE):
                add(f"SMB {match.group(1)}")
        return queries

    def _server_from_http_banner(self, banner: str) -> str | None:
        match = re.search(r"(?:^|\s)Server:\s*([^\r\n]+?)(?:\s+[A-Z][A-Za-z-]+:|$)", banner, flags=re.IGNORECASE)
        if not match:
            return None
        return match.group(1).strip()
