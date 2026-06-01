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

from primordial.core.rag.vuln_sync_sources import VulnFeedSourceMixin


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


class VulnFeedSyncer(VulnFeedSourceMixin):
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
