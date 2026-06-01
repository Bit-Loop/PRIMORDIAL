#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

try:
    import goal_compile
except ModuleNotFoundError:  # pragma: no cover - exercised through package imports.
    from tools import goal_compile


DEFAULT_REMOTE = "origin"
FULL_VALIDATION_COMMAND = ["python3", "-m", "unittest", "discover", "-s", "tests", "-q"]


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class GoalPackError(RuntimeError):
    pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run PRIMORDIAL bounded goal-pack lifecycle checks.")
    parser.add_argument("--root", default=".", help="Repository root.")
    parser.add_argument("--output", default=goal_compile.DEFAULT_OUTPUT, help="Generated instruct path.")
    parser.add_argument("--current-output", default=goal_compile.DEFAULT_CURRENT, help="Current pointer path.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Show the active pack lifecycle state.")
    subparsers.add_parser("preflight", help="Fail closed unless the active pack is ready for work.")

    finish = subparsers.add_parser("finish", help="Validate, commit, push, and switch to the next pack branch.")
    finish.add_argument("--remote", default=DEFAULT_REMOTE, help="Remote to push to.")
    finish.add_argument("--no-push", action="store_true", help="Do not push after committing.")
    finish.add_argument("--no-switch", action="store_true", help="Do not switch to the next pack branch after commit.")
    finish.add_argument("--message", help="Commit message. Defaults to 'Complete <pack> goal pack'.")
    finish.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip validation command execution. Intended only for isolated unit tests.",
    )

    args = parser.parse_args(argv)
    root = Path(args.root).resolve()

    try:
        if args.command == "status":
            print_status(root, output=args.output, current_output=args.current_output)
        elif args.command == "preflight":
            preflight(root, output=args.output, current_output=args.current_output)
        elif args.command == "finish":
            finish_pack(
                root,
                output=args.output,
                current_output=args.current_output,
                remote=args.remote,
                push=not args.no_push,
                switch_to_next=not args.no_switch,
                message=args.message,
                skip_validation=args.skip_validation,
            )
        else:
            raise GoalPackError(f"unknown command: {args.command}")
    except (GoalPackError, goal_compile.GoalConfigError) as exc:
        print(f"ERROR: {exc}")
        return 1
    return 0


def print_status(root: Path, *, output: str, current_output: str) -> None:
    status = lifecycle_status(root, output=output, current_output=current_output)
    print(f"active_pack: {status['active_pack']}")
    print(f"active_milestones: {', '.join(status['active_milestones'])}")
    print(f"active_pack_complete: {'yes' if status['active_pack_complete'] else 'no'}")
    print(f"overall_completion: {status['overall_completion_percent']}%")
    print(f"branch: {status['branch'] or '<detached>'}")
    print(f"dirty: {'yes' if status['dirty'] else 'no'}")
    print(f"upstream: {status['upstream'] or '<none>'}")
    print(f"next_pack: {status['next_pack'] or '<none>'}")
    print(f"next_branch: {status['next_branch'] or '<none>'}")


def lifecycle_status(root: Path, *, output: str, current_output: str) -> dict[str, Any]:
    current = _load_current(root, current_output)
    config = goal_compile.load_goal_config(root)
    branch = current_branch(root)
    next_pack = str(current.get("next_slice_pack") or "")
    return {
        "active_pack": str(current.get("active_slice_pack", "")),
        "active_milestones": _text_list(current.get("active_milestones")),
        "active_pack_complete": bool(current.get("active_pack_complete")),
        "overall_completion_percent": current.get("overall_completion_percent", 0),
        "branch": branch,
        "dirty": bool(worktree_status(root)),
        "upstream": upstream_branch(root),
        "next_pack": next_pack,
        "next_branch": next_branch_name(branch, next_pack) if next_pack else "",
        "declared_pack_count": len(goal_compile.list_slice_packs(config)),
    }


def preflight(root: Path, *, output: str, current_output: str) -> None:
    errors: list[str] = []
    errors.extend(goal_compile.lint_config(goal_compile.load_goal_config(root)))
    try:
        errors.extend(goal_compile.verify_generated(root, output=output, current_output=current_output))
    except goal_compile.GoalConfigError as exc:
        errors.append(str(exc))
    status = worktree_status(root)
    if status:
        errors.append("worktree is dirty; finish or stash current changes before starting a new pack")
    branch = current_branch(root)
    if not branch:
        errors.append("repository is in detached HEAD state")
    elif branch_ref_errors(root, branch):
        errors.extend(branch_ref_errors(root, branch))
    if errors:
        raise GoalPackError("\n".join(errors))
    active_pack = goal_compile.active_slice_pack_from_current(root, current_output)
    print(f"preflight ok: active_pack={active_pack} branch={branch}")


def finish_pack(
    root: Path,
    *,
    output: str,
    current_output: str,
    remote: str,
    push: bool,
    switch_to_next: bool,
    message: str | None,
    skip_validation: bool = False,
) -> None:
    branch = current_branch(root)
    if not branch:
        raise GoalPackError("repository is in detached HEAD state")
    ref_errors = branch_ref_errors(root, branch)
    if ref_errors:
        raise GoalPackError("\n".join(ref_errors))

    start_pack = goal_compile.active_slice_pack_from_current(root, current_output)
    if not skip_validation:
        run_validation(root, output=output)
    _run_checked(
        root,
        [
            "python3",
            "tools/goal_compile.py",
            "--from-current",
            "--output",
            output,
            "--current-output",
            current_output,
        ],
    )
    active_incomplete = active_pack_incomplete_milestones(root, current_output=current_output)
    if active_incomplete:
        raise GoalPackError(
            "active pack is not fully complete in typed milestones: " + ", ".join(active_incomplete)
        )

    _run_checked(
        root,
        [
            "python3",
            "tools/goal_compile.py",
            "--advance",
            "--output",
            output,
            "--current-output",
            current_output,
        ],
    )
    verify_errors = goal_compile.verify_generated(root, output=output, current_output=current_output)
    if verify_errors:
        raise GoalPackError("\n".join(verify_errors))

    _run_checked(root, ["git", "add", "-A"])
    if not staged_status(root):
        raise GoalPackError("nothing to commit after validation and compiler advance")

    commit_message = message or f"Complete {start_pack} goal pack"
    _run_checked(root, ["git", "commit", "-m", commit_message])

    if push:
        push_args = ["git", "push"]
        if not upstream_branch(root):
            push_args.extend(["-u", remote, "HEAD"])
        else:
            push_args.append(remote)
        _run_checked(root, push_args)

    next_pack = goal_compile.active_slice_pack_from_current(root, current_output)
    if switch_to_next and next_pack and next_pack != start_pack:
        branch_name = next_branch_name(branch, next_pack)
        if not branch_name:
            raise GoalPackError(f"could not derive next branch for active pack: {next_pack}")
        if branch_exists(root, branch_name):
            _run_checked(root, ["git", "switch", branch_name])
        else:
            _run_checked(root, ["git", "switch", "-c", branch_name])
        print(f"switched to next pack branch: {branch_name}")

    print(f"finish ok: completed_pack={start_pack} next_pack={next_pack}")


def run_validation(root: Path, *, output: str) -> None:
    for command in validation_commands_from_instruct(root / output):
        _run_checked(root, shlex.split(command))
    _run_checked(root, FULL_VALIDATION_COMMAND)
    _run_checked(root, ["python3", "tools/goal_compile.py", "--check"])
    _run_checked(root, ["python3", "tools/goal_compile.py", "--verify-generated"])
    _run_checked(root, ["git", "diff", "--check"])


def validation_commands_from_instruct(path: Path) -> list[str]:
    commands: list[str] = []
    in_section = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "Validation commands:":
            in_section = True
            continue
        if in_section and line and not line.startswith("- "):
            break
        if in_section and line.startswith("- "):
            command = line[2:].strip()
            if command:
                commands.append(command)
    return list(dict.fromkeys(commands))


def active_pack_incomplete_milestones(root: Path, *, current_output: str) -> list[str]:
    current = _load_current(root, current_output)
    progress = current.get("milestone_progress")
    if not isinstance(progress, dict):
        raise GoalPackError("current task pointer missing milestone_progress")
    incomplete: list[str] = []
    for milestone in _text_list(current.get("active_milestones")):
        item = progress.get(milestone)
        if not isinstance(item, dict) or item.get("status") != "fully_complete" or item.get("completion_percent") != 100:
            incomplete.append(milestone)
    return incomplete


def next_branch_name(current: str, next_pack: str) -> str:
    if not next_pack:
        return ""
    match = re.match(r"^phase(\d+)-", current or "")
    if match:
        return f"phase{int(match.group(1)) + 1}-{next_pack}"
    return f"phase-next-{next_pack}"


def worktree_status(root: Path) -> str:
    return _run_git(root, "status", "--porcelain=v1", "--untracked-files=all").stdout.strip()


def staged_status(root: Path) -> str:
    return _run_git(root, "diff", "--cached", "--name-status").stdout.strip()


def current_branch(root: Path) -> str:
    return _run_git(root, "branch", "--show-current").stdout.strip()


def upstream_branch(root: Path) -> str:
    result = _run_git(root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}", check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def branch_exists(root: Path, branch: str) -> bool:
    return _run_git(root, "show-ref", "--verify", "--quiet", f"refs/heads/{branch}", check=False).returncode == 0


def branch_ref_errors(root: Path, branch: str) -> list[str]:
    errors: list[str] = []
    git_dir = _git_dir(root)
    for rel_path in (Path("refs") / "heads" / branch, Path("logs") / "refs" / "heads" / branch):
        path = git_dir / rel_path
        if path.exists():
            if not os.access(path, os.W_OK):
                errors.append(f"git branch path is not writable: {path}")
        elif not os.access(path.parent, os.W_OK):
            errors.append(f"git branch directory is not writable: {path.parent}")
    packed_refs = git_dir / "packed-refs"
    if packed_refs.exists() and not os.access(packed_refs, os.W_OK):
        errors.append(f"git packed refs file is not writable: {packed_refs}")
    return errors


def _git_dir(root: Path) -> Path:
    result = _run_git(root, "rev-parse", "--git-dir")
    git_dir = Path(result.stdout.strip())
    return git_dir if git_dir.is_absolute() else root / git_dir


def _load_current(root: Path, current_output: str) -> dict[str, Any]:
    path = root / current_output
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GoalPackError(f"missing current task pointer: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GoalPackError(f"invalid current task pointer JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise GoalPackError(f"current task pointer must be a JSON object: {path}")
    return payload


def _run_git(root: Path, *args: str, check: bool = True) -> CommandResult:
    return _run_command(root, ["git", *args], check=check)


def _run_checked(root: Path, command: Sequence[str]) -> CommandResult:
    print("$ " + " ".join(shlex.quote(part) for part in command))
    return _run_command(root, command, check=True)


def _run_command(root: Path, command: Sequence[str], *, check: bool) -> CommandResult:
    result = subprocess.run(
        list(command),
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    command_result = CommandResult(result.returncode, result.stdout, result.stderr)
    if check and command_result.returncode != 0:
        detail = (command_result.stderr or command_result.stdout).strip()
        raise GoalPackError(f"command failed ({command_result.returncode}): {' '.join(command)}\n{detail}")
    return command_result


def _text_list(value: Any) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


if __name__ == "__main__":
    raise SystemExit(main())
