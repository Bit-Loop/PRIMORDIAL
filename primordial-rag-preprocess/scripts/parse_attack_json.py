#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from primordial_preprocess.extraction.json_attack import parse_attack_file, write_attack_outputs  # noqa: E402
from primordial_preprocess.filetypes import attack_domain_from_filename  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse one or more MITRE ATT&CK JSON bundles structurally.")
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--output-dir", default=Path("primordial-rag-preprocess/output"), type=Path)
    args = parser.parse_args()
    by_domain: dict[str, list[dict]] = {}
    for path in args.files:
        domain = attack_domain_from_filename(path.name) or "attack"
        by_domain.setdefault(domain, []).extend(parse_attack_file(path))
    write_attack_outputs(by_domain, args.output_dir)
    print(f"attack parse complete: {sum(len(records) for records in by_domain.values())} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
