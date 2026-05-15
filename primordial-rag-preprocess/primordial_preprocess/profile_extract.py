from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .config import CorpusPolicy
from .models import ALLOWED_USE_MODES, SecurityDocProfile, domains_from_corpus_types


def build_profiles(
    records: list[dict[str, Any]],
    extracted: list[dict[str, Any]],
    output_dir: Path | str,
    policy: CorpusPolicy,
    *,
    skip_vlm: bool = True,
    force: bool = False,
) -> list[dict[str, Any]]:
    out = Path(output_dir)
    profile_dir = out / "profiles"
    profile_dir.mkdir(parents=True, exist_ok=True)
    extracted_by_source = {item.get("source_id"): item for item in extracted}
    profiles: list[dict[str, Any]] = []
    for record in records:
        source_id = str(record["source_id"])
        profile_path = profile_dir / f"{source_id}.profile.json"
        if profile_path.exists() and not force:
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
        else:
            profile = _profile_for_record(record)
            maybe_extracted = extracted_by_source.get(source_id, {})
            if policy.vlm_profile_extraction and not skip_vlm:
                profile = _try_docling_profile(record, maybe_extracted, profile)
            profile_path.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        profiles.append({"source_id": source_id, "profile_path": str(profile_path), "profile": profile})
    _write_jsonl(out / "profiles.jsonl", profiles)
    return profiles


def load_profiles(output_dir: Path | str) -> dict[str, dict[str, Any]]:
    profile_dir = Path(output_dir) / "profiles"
    profiles: dict[str, dict[str, Any]] = {}
    if not profile_dir.exists():
        return profiles
    for path in sorted(profile_dir.glob("*.profile.json")):
        source_id = path.name.removesuffix(".profile.json")
        profiles[source_id] = json.loads(path.read_text(encoding="utf-8"))
    return profiles


def _profile_for_record(record: dict[str, Any]) -> dict[str, Any]:
    primary, secondary = domains_from_corpus_types([str(item) for item in record.get("corpus_type", [])])
    title = str(record.get("title_guess") or record.get("filename") or "")
    profile = SecurityDocProfile(
        title=title,
        author_or_org=str(record.get("publisher_guess") or "") or None,
        year=_year(record.get("year_guess")),
        primary_domain=primary,
        secondary_domains=secondary,
        main_topics=_main_topics(record),
        security_frameworks=_frameworks(record),
        owasp_categories=_owasp_categories(record),
        mitre_techniques=[],
        difficulty=_difficulty(record),
        best_use_modes=list(ALLOWED_USE_MODES),
        requires_authorized_scope=True,
        summary=f"Heuristic profile for {title or record.get('filename')}.",
        retrieval_priority=_retrieval_priority(record),
    )
    return profile.model_dump()


def _try_docling_profile(
    record: dict[str, Any],
    extracted: dict[str, Any],
    fallback: dict[str, Any],
) -> dict[str, Any]:
    if str(record.get("detected_type")) not in {"pdf", "image"}:
        return fallback
    if not extracted.get("extracted") or not record.get("original_path"):
        return fallback
    try:
        from docling.datamodel.base_models import InputFormat
        from docling.document_extractor import DocumentExtractor
    except Exception:
        return fallback
    try:
        extractor = DocumentExtractor(allowed_formats=[InputFormat.PDF, InputFormat.IMAGE])
        result = extractor.extract(
            source=str(record["original_path"]),
            template=SecurityDocProfile,
            raises_on_error=False,
            max_num_pages=5,
            page_range=(1, 5),
        )
    except Exception:
        return fallback
    pages = getattr(result, "pages", []) or []
    for page in pages:
        data = getattr(page, "extracted_data", None)
        if isinstance(data, dict):
            try:
                profile = SecurityDocProfile.model_validate({**fallback, **data})
            except Exception:
                continue
            output = profile.model_dump()
            output["profile_source"] = "docling_document_extractor"
            return output
    return fallback


def _year(value: object) -> int | None:
    try:
        return int(str(value)) if str(value).strip() else None
    except ValueError:
        return None


def _main_topics(record: dict[str, Any]) -> list[str]:
    tokens = re.split(r"[^a-z0-9]+", str(record.get("title_guess") or record.get("filename") or "").lower())
    stop = {"pdf", "epub", "md", "the", "and", "for", "with", "edition", "draft"}
    return [token for token in tokens if len(token) > 2 and token not in stop][:12]


def _frameworks(record: dict[str, Any]) -> list[str]:
    text = f"{record.get('filename', '')} {record.get('classification_reason', '')}".lower()
    frameworks: list[str] = []
    for name, marker in [("OWASP", "owasp"), ("MITRE ATT&CK", "attack"), ("NIST", "nist"), ("PTES", "ptes"), ("Kubernetes", "kubernetes")]:
        if marker in text:
            frameworks.append(name)
    return frameworks


def _owasp_categories(record: dict[str, Any]) -> list[str]:
    filename = str(record.get("filename") or "").lower()
    match = re.match(r"0x(a\d+|aa)-(.+)\.md$", filename)
    return [match.group(1).upper()] if match else []


def _difficulty(record: dict[str, Any]) -> str:
    authority = str(record.get("authority_level") or "")
    risk = str(record.get("risk_level") or "")
    if risk in {"exploit_validation", "post_exploitation_sensitive"}:
        return "expert"
    if authority in {"research_foundation", "advanced_practical"}:
        return "advanced"
    if authority in {"official_standard", "official_governance"}:
        return "intermediate"
    return "unknown"


def _retrieval_priority(record: dict[str, Any]) -> int:
    authority = str(record.get("authority_level") or "")
    if authority in {"official_standard", "official_governance", "official_taxonomy"}:
        return 5
    if authority in {"research_foundation", "research_practical_bridge"}:
        return 4
    if authority in {"explanatory_practical", "advanced_practical", "legacy_reference"}:
        return 3
    if authority in {"tool_reference", "low_authority", "junk"}:
        return 1
    return 2


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
