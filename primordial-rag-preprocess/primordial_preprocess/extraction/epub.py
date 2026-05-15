from __future__ import annotations

from pathlib import Path
from typing import Any

from primordial_preprocess.extraction.docling import extract_with_docling


def extract(path: Path, *, allow_ocr: bool = False) -> dict[str, Any]:
    return extract_with_docling(path, allow_ocr=allow_ocr)
