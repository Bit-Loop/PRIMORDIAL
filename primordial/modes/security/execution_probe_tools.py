from __future__ import annotations

from primordial.modes.security.execution_common import *


class PrimitiveProbeToolMixin:
    def _build_probe_plans(self, assets) -> list[dict[str, str]]:
        hostname_assets = [asset.asset for asset in assets if asset.asset_type == "hostname"]
        plans: list[dict[str, str]] = []
        seen: set[tuple[str, str | None]] = set()

        def add(url: str, asset_label: str, host_header: str | None = None) -> None:
            key = (url, host_header)
            if key in seen:
                return
            seen.add(key)
            plans.append({"url": url, "asset_label": asset_label, "host_header": host_header or ""})

        for asset in assets:
            if asset.asset_type == "webapp" or asset.asset.startswith(("http://", "https://")):
                add(asset.asset, asset.asset)
            elif asset.asset_type == "hostname":
                add(f"http://{asset.asset}/", asset.asset)
                add(f"https://{asset.asset}/", asset.asset)
            elif asset.asset_type == "ip":
                add(f"http://{asset.asset}/", asset.asset)
                add(f"https://{asset.asset}/", asset.asset)
                for hostname in hostname_assets:
                    add(f"http://{asset.asset}/", f"{asset.asset} ({hostname})", host_header=hostname)
                    add(f"https://{asset.asset}/", f"{asset.asset} ({hostname})", host_header=hostname)
        return plans

    def _probe_url(self, *, url: str, host_header: str | None, asset_label: str) -> dict[str, object]:
        headers = {"User-Agent": "Primordial/0.1", "Accept": "*/*"}
        if host_header:
            headers["Host"] = host_header
        resolved_ips = self._resolve_hostnames(url, host_header)
        last_error = ""

        for insecure_tls in (False, True):
            parsed = parse.urlsplit(url)
            if parsed.scheme != "https" and insecure_tls:
                continue
            try:
                request_object = request.Request(url, headers=headers, method="GET")
                context = ssl._create_unverified_context() if insecure_tls and parsed.scheme == "https" else None
                with request.urlopen(request_object, timeout=8, context=context) as response:
                    body = response.read(262144)
                    return self._normalize_probe_response(
                        asset_label=asset_label,
                        requested_url=url,
                        effective_url=response.geturl(),
                        status_code=response.status,
                        response_headers=response.headers,
                        body=body,
                        resolved_ips=resolved_ips,
                        ssl_verification_disabled=insecure_tls,
                        host_header=host_header,
                    )
            except error.HTTPError as exc:
                body = exc.read(262144)
                return self._normalize_probe_response(
                    asset_label=asset_label,
                    requested_url=url,
                    effective_url=exc.geturl(),
                    status_code=exc.code,
                    response_headers=exc.headers,
                    body=body,
                    resolved_ips=resolved_ips,
                    ssl_verification_disabled=insecure_tls,
                    host_header=host_header,
                )
            except Exception as exc:  # noqa: BLE001 - capture probe failures into evidence
                last_error = str(exc)

        return {
            "asset_label": asset_label,
            "requested_url": url,
            "resolved_ips": resolved_ips,
            "error": last_error or "probe failed",
        }

    def _normalize_probe_response(
        self,
        *,
        asset_label: str,
        requested_url: str,
        effective_url: str,
        status_code: int,
        response_headers,
        body: bytes,
        resolved_ips: list[str],
        ssl_verification_disabled: bool,
        host_header: str | None,
    ) -> dict[str, object]:
        headers = {key.lower(): value for key, value in response_headers.items()}
        content_type = headers.get("content-type", "")
        decoded = self._decode_response_body(body, response_headers)
        parser = _SurfaceParser()
        if "html" in content_type and decoded:
            try:
                parser.feed(decoded)
            except Exception:  # noqa: BLE001 - malformed HTML should not break recon
                pass
        discovery_results = self._run_content_discovery(effective_url, host_header)
        return {
            "asset_label": asset_label,
            "requested_url": requested_url,
            "effective_url": effective_url,
            "status_code": status_code,
            "content_type": content_type,
            "headers": self._sanitize_response_headers(headers),
            "headers_redacted": True,
            "title": parser.title,
            "page_links": self._sanitize_surface_urls(parser.links)[:self.config.max_evidence_items],
            "scripts": self._sanitize_surface_urls(parser.scripts)[:self.config.max_evidence_items],
            "forms": self._sanitize_surface_urls(parser.forms)[:self.config.max_evidence_items],
            "surface_urls_redacted": True,
            "resolved_ips": resolved_ips,
            "discovery_results": discovery_results,
            "ssl_verification_disabled": ssl_verification_disabled,
            "host_header": host_header or "",
        }

    def _sanitize_response_headers(self, headers: dict[str, str]) -> dict[str, str]:
        sensitive = {
            "authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "x-auth-token",
            "x-csrf-token",
            "x-xsrf-token",
        }
        sanitized: dict[str, str] = {}
        for key, value in headers.items():
            normalized = str(key).strip().lower()
            if normalized in sensitive or "token" in normalized or "secret" in normalized:
                sanitized[normalized] = "<redacted>"
            else:
                sanitized[normalized] = str(value)
        return sanitized

    def _sanitize_surface_urls(self, values: list[str]) -> list[str]:
        sanitized: list[str] = []
        for value in values:
            sanitized.append(self._sanitize_surface_url(value))
        return sanitized

    def _sanitize_surface_url(self, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        parsed = parse.urlsplit(text)
        if not parsed.query:
            return text
        redacted_query = parse.urlencode([(key, "<redacted>") for key, _ in parse.parse_qsl(parsed.query, keep_blank_values=True)])
        return parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, redacted_query, parsed.fragment))

    def _run_content_discovery(self, base_url: str, host_header: str | None) -> list[dict[str, object]]:
        parsed = parse.urlsplit(base_url)
        if parsed.scheme not in {"http", "https"}:
            return []
        discovery_headers = {"User-Agent": "Primordial/0.1", "Accept": "*/*"}
        if host_header:
            discovery_headers["Host"] = host_header
        results: list[dict[str, object]] = []
        for path in DISCOVERY_PATHS:
            candidate = parse.urljoin(base_url, path)
            try:
                request_object = request.Request(candidate, headers=discovery_headers, method="GET")
                with request.urlopen(
                    request_object,
                    timeout=5,
                    context=ssl._create_unverified_context() if parsed.scheme == "https" else None,
                ) as response:
                    results.append(
                        {
                            "path": path,
                            "url": response.geturl(),
                            "status": response.status,
                            "content_type": response.headers.get("Content-Type", ""),
                        }
                    )
            except error.HTTPError as exc:
                if exc.code in {401, 403, 404}:
                    results.append(
                        {
                            "path": path,
                            "url": exc.geturl(),
                            "status": exc.code,
                            "content_type": exc.headers.get("Content-Type", ""),
                        }
                    )
            except Exception:
                continue
        return results

    def _resolve_hostnames(self, url: str, host_header: str | None) -> list[str]:
        host = host_header or parse.urlsplit(url).hostname
        if not host:
            return []
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return []
        return sorted({info[4][0] for info in infos})

    def _decode_response_body(self, body: bytes, response_headers) -> str:
        charset = response_headers.get_content_charset() if hasattr(response_headers, "get_content_charset") else None
        for encoding in filter(None, [charset, "utf-8", "latin-1"]):
            try:
                return body.decode(encoding)
            except UnicodeDecodeError:
                continue
        return ""

    def _normalize_paths(self, values: list[str]) -> list[str]:
        normalized: set[str] = set()
        for value in values:
            parsed = parse.urlsplit(value)
            path = parsed.path if parsed.scheme else value
            if not isinstance(path, str) or not path:
                continue
            if path.startswith("/"):
                normalized.add(path)
        return sorted(normalized)

    def _extract_query_parameter_names(self, values: list[str]) -> list[str]:
        names: set[str] = set()
        for value in values:
            parsed = parse.urlsplit(value)
            for key in parse.parse_qs(parsed.query).keys():
                if key:
                    names.add(key)
        return sorted(names)

    def _extract_auth_surfaces(self, values: list[str]) -> list[str]:
        surfaces: set[str] = set()
        for value in values:
            lowered = value.lower()
            if any(keyword in lowered for keyword in AUTH_KEYWORDS):
                parsed = parse.urlsplit(value)
                surfaces.add(parsed.path or value)
        return sorted(surfaces)

    def _summarize_probe(self, probe: dict[str, object]) -> str:
        title = f" title={probe['title']!r}" if probe["title"] else ""
        return (
            f"HTTP probe returned {probe['status_code']} for {probe['effective_url']} "
            f"with content-type {probe['content_type'] or 'unknown'}."
            f"{title}"
        )

    def _build_recon_summary(
        self,
        probes: list[dict[str, object]],
        auth_surfaces: set[str],
        discovered_paths: set[str],
        discovered_parameters: set[str],
    ) -> str:
        lines = [
            f"Reachable endpoints: {len(probes)}",
            f"Observed auth-adjacent surfaces: {', '.join(sorted(auth_surfaces)[:10]) or 'none'}",
            f"Observed paths: {', '.join(sorted(discovered_paths)[:12]) or 'none'}",
            f"Observed query parameters: {', '.join(sorted(discovered_parameters)[:12]) or 'none'}",
        ]
        for probe in probes[:6]:
            lines.append(
                f"- {probe['effective_url']} -> {probe['status_code']} {probe['content_type'] or 'unknown'}"
            )
        return "\n".join(lines)

    def _build_analysis_summary(
        self,
        observed_paths: list[str],
        observed_parameters: list[str],
        auth_ref_count: int,
    ) -> str:
        return (
            f"Evidence-backed surface review found {len(observed_paths)} normalized paths and "
            f"{len(observed_parameters)} normalized query parameter names. "
            f"Auth-adjacent evidence refs: {auth_ref_count}. "
            "No exploit claim is promoted at this stage."
        )

    def _artifact_prefix_for_probe(self, asset_label: str, url: str) -> str:
        parsed = parse.urlsplit(url)
        host = "".join(
            character if character.isalnum() else "_"
            for character in asset_label
        ).strip("_")
        scheme = parsed.scheme or "http"
        return f"recon-{host}-{scheme}"
