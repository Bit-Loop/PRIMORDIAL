from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import csv
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable
from urllib import error, parse, request


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_CSV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"
CVELIST_V5_RAW_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"


UrlOpen = Callable[..., Any]


@dataclass(slots=True)
class VulnSyncOptions:
    since_year: int = 2020
    embed_all: bool = True
    sources: set[str] = field(default_factory=lambda: {"nvd", "kev", "epss", "cvelist_v5", "osv", "ghsa"})
    raw_dir: Path | None = None
    output_dir: Path | None = None
    timeout_seconds: float = 45.0
    rate_limit_seconds: float | None = None
    max_nvd_pages: int | None = None
    max_enrichment_cves: int = 250
    allow_ocr: bool = False


class VulnFeedSyncer:
    def __init__(
        self,
        project_root: Path | str,
        *,
        preprocess_root: Path | str | None = None,
        opener: UrlOpen | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.preprocess_root = Path(preprocess_root or self.project_root / "primordial-rag-preprocess").resolve()
        self._opener = opener or request.urlopen
        self._sleep = sleeper or time.sleep

    def sync(self, options: VulnSyncOptions | None = None) -> dict[str, Any]:
        options = options or VulnSyncOptions()
        raw_dir = (options.raw_dir or self.project_root / "primordial-rag-preprocess" / "data_raw" / "vuln").resolve()
        output_dir = (options.output_dir or self.project_root / "primordial-rag-preprocess" / "output").resolve()
        started_at = _utc_now()
        source_results: dict[str, dict[str, Any]] = {}
        collected_cves: set[str] = set()

        raw_dir.mkdir(parents=True, exist_ok=True)
        if "nvd" in options.sources:
            result, cves = self._sync_nvd(raw_dir, options)
            source_results["nvd"] = result
            collected_cves.update(cves)
        if "kev" in options.sources:
            result, cves = self._sync_kev(raw_dir, options)
            source_results["kev"] = result
            collected_cves.update(cves)

        enrichment_cves = sorted(collected_cves)[: max(0, int(options.max_enrichment_cves))]
        if "epss" in options.sources:
            result = self._sync_epss(raw_dir, enrichment_cves, options)
            source_results["epss"] = result
        if "cvelist_v5" in options.sources:
            result = self._sync_cvelist_v5(raw_dir, enrichment_cves, options)
            source_results["cvelist_v5"] = result
        if "osv" in options.sources:
            result = self._sync_osv(raw_dir, enrichment_cves, options)
            source_results["osv"] = result
        if "ghsa" in options.sources:
            result = self._sync_ghsa(raw_dir, enrichment_cves, options)
            source_results["ghsa"] = result

        preprocess_manifest = self._run_preprocessor(raw_dir, output_dir, options)
        finished_at = _utc_now()
        summary = {
            "ok": True,
            "started_at": started_at.isoformat(),
            "completed_at": finished_at.isoformat(),
            "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
            "since_year": int(options.since_year),
            "embed_all": bool(options.embed_all),
            "raw_dir": str(raw_dir),
            "output_dir": str(output_dir),
            "chunks_dir": str(output_dir / "vuln" / "chunks"),
            "sources": source_results,
            "source_failures": {
                source: result
                for source, result in source_results.items()
                if result.get("status") not in {"ok", "partial", "skipped"}
                or int(result.get("failures") or 0) > 0
            },
            "cve_ids_seen": len(collected_cves),
            "cve_ids_enriched": len(enrichment_cves),
            "preprocess_manifest": preprocess_manifest,
            "safety": {
                "control_plane_output": "hints_only",
                "blocks_action_selection": True,
                "blocks_scope_expansion": True,
            },
        }
        self._write_json(output_dir / "vuln" / "status" / "vuln_sync_status.json", summary)
        return summary

    def _sync_nvd(self, raw_dir: Path, options: VulnSyncOptions) -> tuple[dict[str, Any], set[str]]:
        result = self._source_result("nvd")
        cves: set[str] = set()
        api_key = os.getenv("NVD_API_KEY", "").strip()
        headers = {"User-Agent": "Primordial vulnerability RAG sync"}
        if api_key:
            headers["apiKey"] = api_key
        rate_limit = options.rate_limit_seconds
        if rate_limit is None:
            rate_limit = 0.6 if api_key else 6.0
        start = datetime(max(1999, int(options.since_year)), 1, 1, tzinfo=timezone.utc)
        end_limit = _utc_now()
        pages_seen = 0
        try:
            for window_start, window_end in _nvd_windows(start, end_limit):
                start_index = 0
                total_results = None
                while total_results is None or start_index < total_results:
                    if options.max_nvd_pages is not None and pages_seen >= options.max_nvd_pages:
                        result["status"] = "partial"
                        result["truncated"] = True
                        result["limit"] = options.max_nvd_pages
                        result["records"] = len(cves)
                        return result, cves
                    params = {
                        "pubStartDate": _nvd_timestamp(window_start),
                        "pubEndDate": _nvd_timestamp(window_end),
                        "startIndex": str(start_index),
                        "resultsPerPage": "2000",
                    }
                    payload = self._fetch_json(f"{NVD_API_URL}?{parse.urlencode(params)}", headers=headers, timeout=options.timeout_seconds)
                    if not isinstance(payload, dict):
                        raise ValueError("NVD response was not a JSON object")
                    total_results = int(payload.get("totalResults") or 0)
                    vulnerabilities = payload.get("vulnerabilities") if isinstance(payload.get("vulnerabilities"), list) else []
                    file_path = (
                        raw_dir
                        / "structured"
                        / "nvd"
                        / str(window_start.year)
                        / f"nvd_{window_start.date()}_{window_end.date()}_{start_index}.json"
                    )
                    self._write_json(file_path, payload)
                    result["files_written"] += 1
                    pages_seen += 1
                    for row in vulnerabilities:
                        cve_id = _cve_id_from_nvd_row(row)
                        if cve_id:
                            cves.add(cve_id)
                    result["records"] += len(vulnerabilities)
                    start_index += max(1, int(payload.get("resultsPerPage") or len(vulnerabilities) or 1))
                    if start_index < total_results and rate_limit > 0:
                        self._sleep(float(rate_limit))
                if rate_limit > 0:
                    self._sleep(float(rate_limit))
        except Exception as exc:  # noqa: BLE001 - sync status must preserve source failures
            result["status"] = "failed" if not cves else "partial"
            result["failures"] += 1
            result["errors"].append(str(exc))
        result["records"] = max(int(result["records"]), len(cves))
        return result, cves

    def _sync_kev(self, raw_dir: Path, options: VulnSyncOptions) -> tuple[dict[str, Any], set[str]]:
        result = self._source_result("kev")
        cves: set[str] = set()
        errors: list[str] = []
        try:
            text = self._fetch_text(CISA_KEV_CSV_URL, timeout=options.timeout_seconds)
            rows = list(csv.DictReader(text.splitlines()))
            for row in rows:
                cve_id = str(row.get("cveID") or row.get("cve_id") or "").upper()
                if cve_id.startswith("CVE-"):
                    cves.add(cve_id)
            path = raw_dir / "structured" / "kev" / "known_exploited_vulnerabilities.csv"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            result["files_written"] = 1
            result["records"] = len(rows)
            return result, cves
        except Exception as exc:  # noqa: BLE001
            errors.append(f"csv: {exc}")
        try:
            payload = self._fetch_json(CISA_KEV_URL, timeout=options.timeout_seconds)
            if not isinstance(payload, dict):
                raise ValueError("CISA KEV response was not a JSON object")
            rows = payload.get("vulnerabilities") if isinstance(payload.get("vulnerabilities"), list) else []
            for row in rows:
                if isinstance(row, dict):
                    cve_id = str(row.get("cveID") or row.get("cve_id") or "").upper()
                    if cve_id.startswith("CVE-"):
                        cves.add(cve_id)
            self._write_json(raw_dir / "structured" / "kev" / "known_exploited_vulnerabilities.json", payload)
            result["files_written"] = 1
            result["records"] = len(rows)
        except Exception as exc:  # noqa: BLE001
            result["status"] = "failed"
            result["failures"] += 1
            result["errors"].extend([*errors, f"json: {exc}"])
        return result, cves

    def _sync_epss(self, raw_dir: Path, cve_ids: list[str], options: VulnSyncOptions) -> dict[str, Any]:
        result = self._source_result("epss")
        if not cve_ids:
            result["status"] = "skipped"
            result["skip_reason"] = "no CVE IDs available for EPSS enrichment"
            return result
        rows: list[dict[str, str]] = []
        for batch in _batches(cve_ids, 100):
            try:
                url = f"{FIRST_EPSS_URL}?{parse.urlencode({'cve': ','.join(batch)})}"
                payload = self._fetch_json(url, timeout=options.timeout_seconds)
                data = payload.get("data") if isinstance(payload, dict) and isinstance(payload.get("data"), list) else []
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    rows.append(
                        {
                            "cve": str(item.get("cve") or "").upper(),
                            "epss": str(item.get("epss") or ""),
                            "percentile": str(item.get("percentile") or ""),
                            "date": str(item.get("date") or ""),
                        }
                    )
            except Exception as exc:  # noqa: BLE001
                result["failures"] += 1
                result["errors"].append(str(exc))
        if rows:
            path = raw_dir / "structured" / "epss" / f"epss_{_utc_now().date().isoformat()}.csv"
            self._write_csv(path, rows, ["cve", "epss", "percentile", "date"])
            result["files_written"] = 1
            result["records"] = len(rows)
        if result["failures"]:
            result["status"] = "partial" if rows else "failed"
        return result

    def _sync_cvelist_v5(self, raw_dir: Path, cve_ids: list[str], options: VulnSyncOptions) -> dict[str, Any]:
        result = self._source_result("cvelist_v5")
        if not cve_ids:
            result["status"] = "skipped"
            result["skip_reason"] = "no CVE IDs available for CVEProject enrichment"
            return result
        for cve_id in cve_ids:
            try:
                year, bucket = _cvelist_bucket(cve_id)
                url = f"{CVELIST_V5_RAW_URL}/cves/{year}/{bucket}/{cve_id}.json"
                payload = self._fetch_json(url, timeout=options.timeout_seconds, not_found_ok=True)
                if payload is None:
                    continue
                self._write_json(raw_dir / "structured" / "cve_v5" / str(year) / bucket / f"{cve_id}.json", payload)
                result["files_written"] += 1
                result["records"] += 1
            except Exception as exc:  # noqa: BLE001
                result["failures"] += 1
                result["errors"].append(f"{cve_id}: {exc}")
        if result["failures"]:
            result["status"] = "partial" if result["records"] else "failed"
        return result

    def _sync_osv(self, raw_dir: Path, cve_ids: list[str], options: VulnSyncOptions) -> dict[str, Any]:
        result = self._source_result("osv")
        if not cve_ids:
            result["status"] = "skipped"
            result["skip_reason"] = "no CVE IDs available for OSV enrichment"
            return result
        for cve_id in cve_ids:
            try:
                payload = self._fetch_json(f"{OSV_VULN_URL}/{parse.quote(cve_id)}", timeout=options.timeout_seconds, not_found_ok=True)
                if payload is None:
                    continue
                self._write_json(raw_dir / "structured" / "osv" / f"{cve_id}.json", payload)
                result["files_written"] += 1
                result["records"] += 1
            except Exception as exc:  # noqa: BLE001
                result["failures"] += 1
                result["errors"].append(f"{cve_id}: {exc}")
        if result["failures"]:
            result["status"] = "partial" if result["records"] else "failed"
        return result

    def _sync_ghsa(self, raw_dir: Path, cve_ids: list[str], options: VulnSyncOptions) -> dict[str, Any]:
        result = self._source_result("ghsa")
        if not cve_ids:
            result["status"] = "skipped"
            result["skip_reason"] = "no CVE IDs available for GHSA enrichment"
            return result
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Primordial vulnerability RAG sync",
        }
        token = os.getenv("GITHUB_TOKEN", "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        for cve_id in cve_ids:
            try:
                url = f"{GITHUB_ADVISORIES_URL}?{parse.urlencode({'cve_id': cve_id, 'per_page': '100'})}"
                payload = self._fetch_json(url, headers=headers, timeout=options.timeout_seconds, not_found_ok=True)
                if payload is None:
                    continue
                advisories = payload if isinstance(payload, list) else []
                for index, advisory in enumerate(advisories):
                    if not isinstance(advisory, dict):
                        continue
                    advisory_id = str(advisory.get("ghsa_id") or advisory.get("id") or f"{cve_id}-{index}")
                    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", advisory_id)
                    self._write_json(raw_dir / "structured" / "ghsa" / f"{safe_id}.json", advisory)
                    result["files_written"] += 1
                    result["records"] += 1
            except Exception as exc:  # noqa: BLE001
                result["failures"] += 1
                result["errors"].append(f"{cve_id}: {exc}")
        if result["failures"]:
            result["status"] = "partial" if result["records"] else "failed"
        return result

    def _run_preprocessor(self, raw_dir: Path, output_dir: Path, options: VulnSyncOptions) -> dict[str, Any]:
        package_root = str(self.preprocess_root)
        inserted = False
        if package_root not in sys.path:
            sys.path.insert(0, package_root)
            inserted = True
        try:
            from primordial_preprocess.vuln.run_vuln_stream import run_vuln_stream

            return run_vuln_stream(
                raw_dir=raw_dir,
                output_dir=output_dir,
                embed_all=options.embed_all,
                allow_ocr=options.allow_ocr,
            )
        finally:
            if inserted:
                try:
                    sys.path.remove(package_root)
                except ValueError:
                    pass

    def _fetch_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float,
        not_found_ok: bool = False,
    ) -> Any:
        req = request.Request(url, headers=headers or {"User-Agent": "Primordial vulnerability RAG sync"})
        try:
            with self._opener(req, timeout=timeout) as response:
                raw = response.read()
        except error.HTTPError as exc:
            if not_found_ok and exc.code == 404:
                return None
            raise
        return json.loads(raw.decode("utf-8"))

    def _fetch_text(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float,
    ) -> str:
        req = request.Request(url, headers=headers or {"User-Agent": "Primordial vulnerability RAG sync"})
        with self._opener(req, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")

    def _source_result(self, source: str) -> dict[str, Any]:
        return {
            "source": source,
            "status": "ok",
            "records": 0,
            "files_written": 0,
            "failures": 0,
            "errors": [],
        }

    def _write_json(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _write_csv(self, path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _nvd_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _nvd_windows(start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    windows: list[tuple[datetime, datetime]] = []
    current = start
    max_delta = timedelta(days=119, hours=23, minutes=59)
    while current < end:
        window_end = min(current + max_delta, end)
        windows.append((current, window_end))
        current = window_end + timedelta(seconds=1)
    return windows


def _cve_id_from_nvd_row(row: Any) -> str:
    if not isinstance(row, dict):
        return ""
    cve = row.get("cve") if isinstance(row.get("cve"), dict) else row
    cve_id = str(cve.get("id") or "").upper()
    return cve_id if cve_id.startswith("CVE-") else ""


def _cvelist_bucket(cve_id: str) -> tuple[int, str]:
    match = re.fullmatch(r"CVE-(\d{4})-(\d+)", cve_id.upper())
    if not match:
        raise ValueError(f"invalid CVE ID: {cve_id}")
    year = int(match.group(1))
    number = int(match.group(2))
    return year, f"{number // 1000}xxx"


def _batches(values: list[str], size: int) -> list[list[str]]:
    return [values[index : index + size] for index in range(0, len(values), max(1, size))]
