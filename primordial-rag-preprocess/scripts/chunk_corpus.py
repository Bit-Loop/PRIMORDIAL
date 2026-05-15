#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from primordial_preprocess.chunking import build_chunks  # noqa: E402
from primordial_preprocess.config import load_policy  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Chunk extracted RAG corpus artifacts.")
    parser.add_argument("--output-dir", default=Path("primordial-rag-preprocess/output"), type=Path)
    parser.add_argument("--policy", default=Path("primordial-rag-preprocess/config/corpus_policy.yaml"), type=Path)
    args = parser.parse_args()
    chunks = build_chunks(args.output_dir, load_policy(args.policy))
    print(f"chunking complete: {len(chunks)} chunks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
