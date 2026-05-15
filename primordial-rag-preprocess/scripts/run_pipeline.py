#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from primordial_preprocess.pipeline import run_pipeline  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the PRIMORDIAL RAG preprocessing pipeline.")
    parser.add_argument("--input-dir", type=Path)
    parser.add_argument("--raw-dir", dest="raw_dir", type=Path, help="Alias for --input-dir.")
    parser.add_argument("--output-dir", default=Path("primordial-rag-preprocess/output"), type=Path)
    parser.add_argument("--policy", default=Path("primordial-rag-preprocess/config/corpus_policy.yaml"), type=Path)
    parser.add_argument("--overrides", type=Path)
    parser.add_argument("--force", action="store_true", help="Overwrite existing conversion/profile artifacts.")
    parser.add_argument("--skip-vlm", action="store_true", help="Use heuristic profiles only.")
    parser.add_argument("--skip-docling", action="store_true", help="Skip document conversion; ATT&CK JSON still parses.")
    parser.add_argument(
        "--only",
        choices=["inventory", "dedupe", "convert", "epub", "profiles", "mitre", "chunk", "merge", "eval", "validate"],
        help="Run one pipeline phase group.",
    )
    parser.add_argument("--inventory-only", action="store_true")
    parser.add_argument("--classify-only", action="store_true")
    parser.add_argument("--extract-only", action="store_true")
    parser.add_argument("--chunk-only", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    input_dir = args.input_dir or args.raw_dir
    phase_without_input = args.classify_only or args.extract_only or args.chunk_only or args.validate_only
    if args.only in {"dedupe", "convert", "epub", "profiles", "mitre", "chunk", "merge", "eval", "validate"}:
        phase_without_input = True
    if input_dir is None and not phase_without_input:
        parser.error("--input-dir or --raw-dir is required unless running a phase that uses existing output state")
    result = run_pipeline(
        input_dir=input_dir or Path("."),
        output_dir=args.output_dir,
        policy_path=args.policy,
        overrides_path=args.overrides,
        inventory_only=args.inventory_only,
        classify_only=args.classify_only,
        extract_only=args.extract_only,
        chunk_only=args.chunk_only,
        validate_only=args.validate_only,
        force=args.force,
        skip_vlm=args.skip_vlm,
        skip_docling=args.skip_docling,
        only=args.only,
    )
    print(
        "pipeline complete: "
        f"inventory={result.inventory_count} "
        f"classified={result.classified_count} "
        f"extracted={result.extracted_count} "
        f"chunks={result.chunk_count} "
        f"valid={result.validation_valid}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
