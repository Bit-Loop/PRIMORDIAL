#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from primordial_preprocess.manifest import build_manifest  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Build preprocessing manifest files.")
    parser.add_argument("--output-dir", default=Path("primordial-rag-preprocess/output"), type=Path)
    args = parser.parse_args()
    validation_path = args.output_dir / "validation_report.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8")) if validation_path.exists() else None
    manifest = build_manifest(args.output_dir, validation_report=validation)
    print(f"manifest complete: {manifest['chunks_generated']} chunks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
