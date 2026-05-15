from __future__ import annotations

import re
from pathlib import Path

from primordial_preprocess.hashing import stable_id


def normalize_title(filename: str) -> str:
    stem = Path(filename).stem
    text = re.sub(r"[_-]+", " ", stem)
    text = re.sub(r"\s+", " ", text).strip()
    return text or filename


def guess_year(text: str) -> str:
    match = re.search(r"\b(19[7-9]\d|20[0-3]\d)\b", text)
    return match.group(1) if match else ""


def source_id_for(relative_path: str, sha256: str) -> str:
    return stable_id("source", relative_path, sha256, length=20)


def slug(value: str, *, fallback: str = "item") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-_").lower()
    return cleaned[:100] or fallback
