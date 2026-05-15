#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from primordial_preprocess.classification import classify_sources, write_classification_outputs  # noqa: E402
from primordial_preprocess.config import load_overrides, load_policy  # noqa: E402
from primordial_preprocess.pipeline import read_jsonl  # noqa: E402
from primordial_preprocess.policy import apply_policy  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify inventoried RAG corpus sources.")
    parser.add_argument("--output-dir", default=Path("primordial-rag-preprocess/output"), type=Path)
    parser.add_argument("--policy", default=Path("primordial-rag-preprocess/config/corpus_policy.yaml"), type=Path)
    parser.add_argument("--overrides", type=Path)
    args = parser.parse_args()
    policy = load_policy(args.policy)
    records = read_jsonl(args.output_dir / "inventory.jsonl")
    classified = apply_policy(classify_sources(records), policy, load_overrides(args.overrides))
    write_classification_outputs(classified, args.output_dir)
    print(f"classification complete: {len(classified)} sources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
