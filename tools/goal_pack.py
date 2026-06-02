#!/usr/bin/env python3
from __future__ import annotations

import argparse


RETIRED_MESSAGE = (
    "goal_pack is retired; do not use generated packs, branches, or milestone "
    "bookkeeping to drive completion."
)


class GoalPackError(RuntimeError):
    pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Retired PRIMORDIAL generated-goal pack runner.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default="codex-goal.instruct")
    parser.add_argument("--current-output", default=".goal/current.json")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status")
    subparsers.add_parser("preflight")
    finish = subparsers.add_parser("finish")
    finish.add_argument("--remote", default="origin")
    finish.add_argument("--no-push", action="store_true")
    finish.add_argument("--no-switch", action="store_true")
    finish.add_argument("--message")
    finish.add_argument("--skip-validation", action="store_true")
    parser.parse_args(argv)
    print(f"ERROR: {RETIRED_MESSAGE}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
