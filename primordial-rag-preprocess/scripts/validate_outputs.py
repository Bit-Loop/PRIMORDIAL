#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from primordial_preprocess.config import load_policy  # noqa: E402
from primordial_preprocess.validation import validate_outputs  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate preprocessing output artifacts.")
    parser.add_argument("--output-dir", default=Path("primordial-rag-preprocess/output"), type=Path)
    parser.add_argument("--policy", default=Path("primordial-rag-preprocess/config/corpus_policy.yaml"), type=Path)
    args = parser.parse_args()
    report = validate_outputs(args.output_dir, load_policy(args.policy))
    print(f"validation complete: valid={report['valid']} errors={len(report['errors'])}")
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
