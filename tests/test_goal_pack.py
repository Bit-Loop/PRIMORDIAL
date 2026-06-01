from __future__ import annotations

import io
import json
import shutil
import subprocess
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
import unittest

import yaml

from tools import goal_compile, goal_pack


REPO_ROOT = Path(__file__).resolve().parents[1]


class GoalPackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        shutil.copytree(REPO_ROOT / "goal", self.root / "goal")
        (self.root / "tools").mkdir()
        shutil.copy2(REPO_ROOT / "tools" / "goal_compile.py", self.root / "tools" / "goal_compile.py")
        shutil.copy2(REPO_ROOT / "tools" / "goal_pack.py", self.root / "tools" / "goal_pack.py")
        _git(self.root, "init", "-q")
        _git(self.root, "config", "user.email", "tests@example.invalid")
        _git(self.root, "config", "user.name", "Goal Pack Tests")
        _git(self.root, "checkout", "-q", "-b", "phase2-ctf-harness-controls")
        _run_goal_compile(self.root, "--slice-pack", "ctf-harness-controls")
        _git(self.root, "add", "-A")
        _git(self.root, "commit", "-q", "-m", "initial")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_status_reports_active_pack_and_next_branch(self) -> None:
        result, output = _run_goal_pack(self.root, "status")

        self.assertEqual(result, 0)
        self.assertIn("active_pack: ctf-harness-controls", output)
        self.assertIn("active_milestones: M5, M6", output)
        self.assertIn("dirty: no", output)
        self.assertIn("next_branch: phase3-compiler-bootstrap", output)

    def test_preflight_requires_clean_worktree(self) -> None:
        (self.root / "scratch.txt").write_text("dirty\n", encoding="utf-8")

        result, output = _run_goal_pack(self.root, "preflight")

        self.assertEqual(result, 1)
        self.assertIn("worktree is dirty", output)

    def test_preflight_rejects_stale_generated_outputs(self) -> None:
        (self.root / "codex-goal.instruct").write_text("stale\n", encoding="utf-8")

        result, output = _run_goal_pack(self.root, "preflight")

        self.assertEqual(result, 1)
        self.assertIn("generated instruct is stale", output)

    def test_finish_refuses_to_commit_incomplete_active_pack(self) -> None:
        _mark_active_milestones_incomplete(self.root, {"M5", "M6"})
        (self.root / "implementation.txt").write_text("work that is not evidenced complete\n", encoding="utf-8")

        result, output = _run_goal_pack(self.root, "finish", "--skip-validation", "--no-push", "--no-switch")

        self.assertEqual(result, 1)
        self.assertIn("active pack is not fully complete in typed milestones: M5, M6", output)
        self.assertEqual(_git(self.root, "rev-list", "--count", "HEAD").stdout.strip(), "1")

    def test_finish_commits_advances_and_switches_to_next_pack_branch(self) -> None:
        _complete_active_milestones(self.root, {"M5", "M6"})
        (self.root / "implementation.txt").write_text("completed ctf harness work\n", encoding="utf-8")

        result, output = _run_goal_pack(self.root, "finish", "--skip-validation", "--no-push")

        self.assertEqual(result, 0)
        self.assertIn("finish ok: completed_pack=ctf-harness-controls next_pack=compiler-bootstrap", output)
        self.assertEqual(_git(self.root, "branch", "--show-current").stdout.strip(), "phase3-compiler-bootstrap")
        self.assertEqual(_git(self.root, "rev-list", "--count", "phase2-ctf-harness-controls").stdout.strip(), "2")
        current = json.loads((self.root / ".goal" / "current.json").read_text(encoding="utf-8"))
        self.assertEqual(current["active_slice_pack"], "compiler-bootstrap")

    def test_next_branch_name_increments_phase_prefix(self) -> None:
        self.assertEqual(
            goal_pack.next_branch_name("phase9-something", "ctf-harness-controls"),
            "phase10-ctf-harness-controls",
        )
        self.assertEqual(
            goal_pack.next_branch_name("feature/work", "context-boundaries"),
            "phase-next-context-boundaries",
        )


def _complete_active_milestones(root: Path, milestone_ids: set[str]) -> None:
    milestones_path = root / "goal" / "fragments" / "milestones.yaml"
    payload = yaml.safe_load(milestones_path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    for milestone in payload["milestones"]:
        if milestone["id"] in milestone_ids:
            milestone["status"] = "fully_complete"
            milestone["completion_percent"] = 100
            milestone["evidence"] = [f"unit-test completion evidence for {milestone['id']}"]
    milestones_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    _run_goal_compile(root, "--from-current")


def _mark_active_milestones_incomplete(root: Path, milestone_ids: set[str]) -> None:
    milestones_path = root / "goal" / "fragments" / "milestones.yaml"
    payload = yaml.safe_load(milestones_path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    for milestone in payload["milestones"]:
        if milestone["id"] in milestone_ids:
            milestone["status"] = "in_progress"
            milestone["completion_percent"] = 50
            milestone["evidence"] = [f"unit-test partial evidence for {milestone['id']}"]
    milestones_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    _run_goal_compile(root, "--slice-pack", "ctf-harness-controls")


def _run_goal_compile(root: Path, *args: str) -> tuple[int, str]:
    output = io.StringIO()
    with redirect_stdout(output):
        result = goal_compile.main(["--root", str(root), *args])
    return result, output.getvalue()


def _run_goal_pack(root: Path, *args: str) -> tuple[int, str]:
    output = io.StringIO()
    with redirect_stdout(output):
        result = goal_pack.main(["--root", str(root), *args])
    return result, output.getvalue()


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["git", *args], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result


if __name__ == "__main__":
    unittest.main()
