#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from primordial_preprocess.inventory import inventory_directory, write_inventory_outputs  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory a local RAG corpus directory.")
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output-dir", default=Path("primordial-rag-preprocess/output"), type=Path)
    args = parser.parse_args()
    records = inventory_directory(args.input_dir)
    write_inventory_outputs(records, args.output_dir)
    print(f"inventory complete: {len(records)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
