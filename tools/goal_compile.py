#!/usr/bin/env python3
from __future__ import annotations

import argparse


DEFAULT_OUTPUT = "codex-goal.instruct"
DEFAULT_CURRENT = ".goal/current.json"
RETIRED_MESSAGE = (
    "goal_compile is retired; complete runtime source behavior with behavior tests, "
    "runtime evidence, commits, and pushes instead of generated goal state."
)


class GoalConfigError(ValueError):
    pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Retired PRIMORDIAL generated-goal compiler.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--slice-pack")
    parser.add_argument("--from-current", action="store_true")
    parser.add_argument("--advance", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--verify-generated", action="store_true")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--current-output", default=DEFAULT_CURRENT)
    parser.parse_args(argv)
    print(f"ERROR: {RETIRED_MESSAGE}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
