#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from primordial_preprocess.config import load_policy  # noqa: E402
from primordial_preprocess.extraction.runner import extract_sources  # noqa: E402
from primordial_preprocess.pipeline import read_jsonl  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract allowed sources with Docling only.")
    parser.add_argument("--output-dir", default=Path("primordial-rag-preprocess/output"), type=Path)
    parser.add_argument("--policy", default=Path("primordial-rag-preprocess/config/corpus_policy.yaml"), type=Path)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--skip-docling", action="store_true")
    args = parser.parse_args()
    records = read_jsonl(args.output_dir / "classified_sources.jsonl")
    extracted = extract_sources(records, args.output_dir, load_policy(args.policy), force=args.force, skip_docling=args.skip_docling)
    print(f"extraction complete: {sum(1 for item in extracted if item.get('extracted'))}/{len(extracted)} extracted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
