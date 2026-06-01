from __future__ import annotations

from datetime import datetime, timedelta, timezone
import csv
import os
from pathlib import Path
import re
from urllib import parse
from typing import Any


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_CSV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"
CVELIST_V5_RAW_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"


class VulnFeedSourceMixin:
    def _sync_nvd(self, raw_dir: Path, options: object) -> tuple[dict[str, Any], set[str]]:
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
        pages_seen = 0
        try:
            for window_start, window_end in _nvd_windows(start, _utc_now()):
                pages_seen = self._sync_nvd_window(raw_dir, options, result, cves, headers, rate_limit, pages_seen, window_start, window_end)
                if result.get("truncated"):
                    return result, cves
        except Exception as exc:  # noqa: BLE001 - sync status must preserve source failures
            result["status"] = "failed" if not cves else "partial"
            result["failures"] += 1
            result["errors"].append(str(exc))
        result["records"] = max(int(result["records"]), len(cves))
        return result, cves

    def _sync_nvd_window(
        self,
        raw_dir: Path,
        options: object,
        result: dict[str, Any],
        cves: set[str],
        headers: dict[str, str],
        rate_limit: float,
        pages_seen: int,
        window_start: datetime,
        window_end: datetime,
    ) -> int:
        start_index = 0
        total_results = None
        while total_results is None or start_index < total_results:
            if options.max_nvd_pages is not None and pages_seen >= options.max_nvd_pages:
                result.update({"status": "partial", "truncated": True, "limit": options.max_nvd_pages, "records": len(cves)})
                return pages_seen
            payload = self._fetch_json(_nvd_url(window_start, window_end, start_index), headers=headers, timeout=options.timeout_seconds)
            total_results, vulnerabilities = self._record_nvd_page(raw_dir, payload, window_start, window_end, start_index, result, cves)
            pages_seen += 1
            start_index += max(1, int(payload.get("resultsPerPage") or len(vulnerabilities) or 1))
            if start_index < total_results and rate_limit > 0:
                self._sleep(float(rate_limit))
        if rate_limit > 0:
            self._sleep(float(rate_limit))
        return pages_seen

    def _record_nvd_page(
        self,
        raw_dir: Path,
        payload: dict[str, Any],
        window_start: datetime,
        window_end: datetime,
        start_index: int,
        result: dict[str, Any],
        cves: set[str],
    ) -> tuple[int, list[Any]]:
        if not isinstance(payload, dict):
            raise ValueError("NVD response was not a JSON object")
        total_results = int(payload.get("totalResults") or 0)
        vulnerabilities = payload.get("vulnerabilities") if isinstance(payload.get("vulnerabilities"), list) else []
        file_path = raw_dir / "structured" / "nvd" / str(window_start.year) / f"nvd_{window_start.date()}_{window_end.date()}_{start_index}.json"
        self._write_json(file_path, payload)
        result["files_written"] += 1
        for row in vulnerabilities:
            cve_id = _cve_id_from_nvd_row(row)
            if cve_id:
                cves.add(cve_id)
        result["records"] += len(vulnerabilities)
        return total_results, vulnerabilities

    def _sync_kev(self, raw_dir: Path, options: object) -> tuple[dict[str, Any], set[str]]:
        result = self._source_result("kev")
        cves: set[str] = set()
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
            csv_error = f"csv: {exc}"
        return self._sync_kev_json(raw_dir, options, result, cves, csv_error)

    def _sync_kev_json(
        self,
        raw_dir: Path,
        options: object,
        result: dict[str, Any],
        cves: set[str],
        csv_error: str,
    ) -> tuple[dict[str, Any], set[str]]:
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
            result["errors"].extend([csv_error, f"json: {exc}"])
        return result, cves

    def _sync_epss(self, raw_dir: Path, cve_ids: list[str], options: object) -> dict[str, Any]:
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
                rows.extend(_epss_rows(data))
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

    def _sync_cvelist_v5(self, raw_dir: Path, cve_ids: list[str], options: object) -> dict[str, Any]:
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

    def _sync_osv(self, raw_dir: Path, cve_ids: list[str], options: object) -> dict[str, Any]:
        result = self._source_result("osv")
        if not cve_ids:
            result["status"] = "skipped"
            result["skip_reason"] = "no CVE IDs available for OSV enrichment"
            return result
        return self._sync_simple_json_source(raw_dir, cve_ids, options, result, source="osv")

    def _sync_ghsa(self, raw_dir: Path, cve_ids: list[str], options: object) -> dict[str, Any]:
        result = self._source_result("ghsa")
        if not cve_ids:
            result["status"] = "skipped"
            result["skip_reason"] = "no CVE IDs available for GHSA enrichment"
            return result
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "Primordial vulnerability RAG sync"}
        token = os.getenv("GITHUB_TOKEN", "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        for cve_id in cve_ids:
            self._sync_ghsa_cve(raw_dir, cve_id, options, result, headers)
        if result["failures"]:
            result["status"] = "partial" if result["records"] else "failed"
        return result

    def _sync_simple_json_source(self, raw_dir: Path, cve_ids: list[str], options: object, result: dict[str, Any], *, source: str) -> dict[str, Any]:
        for cve_id in cve_ids:
            try:
                url = f"{OSV_VULN_URL}/{parse.quote(cve_id)}"
                payload = self._fetch_json(url, timeout=options.timeout_seconds, not_found_ok=True)
                if payload is None:
                    continue
                self._write_json(raw_dir / "structured" / source / f"{cve_id}.json", payload)
                result["files_written"] += 1
                result["records"] += 1
            except Exception as exc:  # noqa: BLE001
                result["failures"] += 1
                result["errors"].append(f"{cve_id}: {exc}")
        if result["failures"]:
            result["status"] = "partial" if result["records"] else "failed"
        return result

    def _sync_ghsa_cve(self, raw_dir: Path, cve_id: str, options: object, result: dict[str, Any], headers: dict[str, str]) -> None:
        try:
            url = f"{GITHUB_ADVISORIES_URL}?{parse.urlencode({'cve_id': cve_id, 'per_page': '100'})}"
            payload = self._fetch_json(url, headers=headers, timeout=options.timeout_seconds, not_found_ok=True)
            if payload is None:
                return
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


def _epss_rows(data: list[Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in data:
        if isinstance(item, dict):
            rows.append(
                {
                    "cve": str(item.get("cve") or "").upper(),
                    "epss": str(item.get("epss") or ""),
                    "percentile": str(item.get("percentile") or ""),
                    "date": str(item.get("date") or ""),
                }
            )
    return rows


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _nvd_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _nvd_url(window_start: datetime, window_end: datetime, start_index: int) -> str:
    params = {
        "pubStartDate": _nvd_timestamp(window_start),
        "pubEndDate": _nvd_timestamp(window_end),
        "startIndex": str(start_index),
        "resultsPerPage": "2000",
    }
    return f"{NVD_API_URL}?{parse.urlencode(params)}"


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
