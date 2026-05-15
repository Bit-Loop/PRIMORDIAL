#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from primordial_preprocess.vuln.run_vuln_stream import run_vuln_stream  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PRIMORDIAL vulnerability-intelligence preprocessing.")
    parser.add_argument("--raw-dir", default=Path("primordial-rag-preprocess/data_raw/vuln"), type=Path)
    parser.add_argument("--output-dir", default=Path("primordial-rag-preprocess/output"), type=Path)
    parser.add_argument("--only", choices=["structured", "cve", "nvd", "osv", "ghsa", "kev", "epss", "advisories"])
    parser.add_argument("--embed-all", action="store_true")
    parser.add_argument("--allow-ocr", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_vuln_stream(
        raw_dir=args.raw_dir,
        output_dir=args.output_dir,
        only=args.only,
        embed_all=args.embed_all,
        allow_ocr=args.allow_ocr,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            "vuln stream complete: "
            f"events={result['events']} records={result['records']} cards={result['cards']} "
            f"advisories={result['advisory_docs']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
