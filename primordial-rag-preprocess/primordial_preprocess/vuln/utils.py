from __future__ import annotations

import re
from typing import Any, Iterable


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
GHSA_RE = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE)
OSV_RE = re.compile(r"\b(?:OSV|PYSEC|RUSTSEC|GO|GHSA|DLA|DSA)-[A-Za-z0-9_.:-]+\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
CVSS_RE = re.compile(r"\bCVSS:\d\.\d/[A-Z0-9:/.-]+\b")


def unique(values: Iterable[object]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def upper_ids(values: Iterable[object]) -> list[str]:
    return unique(str(item).upper() for item in values)


def extract_cve_ids(text: str) -> list[str]:
    return upper_ids(CVE_RE.findall(text or ""))


def extract_ghsa_ids(text: str) -> list[str]:
    return upper_ids(GHSA_RE.findall(text or ""))


def extract_cwe_ids(text: str) -> list[str]:
    return upper_ids(CWE_RE.findall(text or ""))


def extract_cvss_vectors(text: str) -> list[str]:
    return unique(CVSS_RE.findall(text or ""))


def first_text(values: Iterable[object]) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def source_ref(url: str, source: str, tags: Iterable[str] = ()) -> dict[str, Any]:
    return {"url": url, "source": source, "tags": unique(tags)}
