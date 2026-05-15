from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any


def convert_epub_with_pandoc(source_path: Path | str, output_path: Path | str, *, force: bool = False) -> dict[str, Any]:
    source = Path(source_path)
    output = Path(output_path)
    if output.exists() and not force:
        return {
            "converted": True,
            "method": "pandoc_cached",
            "output_path": str(output),
            "error": "",
        }
    pandoc = shutil.which("pandoc")
    if not pandoc:
        return {
            "converted": False,
            "method": "pandoc",
            "output_path": str(output),
            "error": "pandoc is not installed; EPUB fallback extractors are disabled",
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            [pandoc, str(source), "-t", "gfm", "-o", str(output)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )
    except Exception as exc:  # noqa: BLE001 - record failure and continue corpus processing
        return {
            "converted": False,
            "method": "pandoc",
            "output_path": str(output),
            "error": f"{type(exc).__name__}: {exc}",
        }
    if completed.returncode != 0:
        return {
            "converted": False,
            "method": "pandoc",
            "output_path": str(output),
            "error": completed.stderr.strip() or completed.stdout.strip() or f"pandoc exited {completed.returncode}",
        }
    return {
        "converted": True,
        "method": "pandoc",
        "output_path": str(output),
        "error": "",
    }
