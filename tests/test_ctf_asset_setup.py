from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from primordial.labs.ctf.asset_setup import setup_phase_assets


class CTFAssetSetupTests(unittest.TestCase):
    def test_phase_three_uses_sparse_clone_and_records_denied_writeup_path(self) -> None:
        calls: list[tuple[str, ...]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("primordial.labs.ctf.asset_setup.shutil.which", return_value="/usr/bin/tool"):
                result = setup_phase_assets(3, lab_root=Path(temp_dir), command_runner=_runner(calls))[0]

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(result.status, "asset_ready")
        clone = next(command for command in calls if command[:2] == ("git", "clone"))
        self.assertEqual(clone[:5], ("git", "clone", "--filter=blob:none", "--depth", "1"))
        self.assertIn("--no-checkout", clone)
        self.assertTrue(any(command[:4] == ("git", "-C", result.asset_path, "sparse-checkout") for command in calls))
        self.assertIn("denied_path=writeup/", evidence)
        self.assertIn("denied_path_removed=writeup/", evidence)
        self.assertIn("asset_setup_only=true", evidence)
        self.assertFalse((Path(result.asset_path) / "writeup").exists())

    def test_phase_five_records_missing_cluster_tooling_without_hiding_asset_clone(self) -> None:
        calls: list[tuple[str, ...]] = []

        def which(tool: str) -> str | None:
            return "/usr/bin/" + tool if tool in {"git", "docker"} else None

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("primordial.labs.ctf.asset_setup.shutil.which", side_effect=which):
                result = setup_phase_assets(5, lab_root=Path(temp_dir), command_runner=_runner(calls))[0]

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(result.status, "tooling_blocked")
        self.assertEqual(result.missing_tools, ("kubectl", "kind", "helm"))
        self.assertIn("missing_tools=kubectl,kind,helm", evidence)
        self.assertIn("git_clone.returncode=0", evidence)

    def test_phase_without_asset_source_is_blocked_with_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = setup_phase_assets(0, lab_root=Path(temp_dir), command_runner=_runner([]))[0]

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(result.status, "blocked")
        self.assertIn("phase has no configured local asset source", result.blocker)
        self.assertIn("status=blocked", evidence)

    def test_failed_clone_marks_phase_blocked_with_command_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("primordial.labs.ctf.asset_setup.shutil.which", return_value="/usr/bin/tool"):
                result = setup_phase_assets(3, lab_root=Path(temp_dir), command_runner=_failing_clone_runner())[0]
            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(result.status, "blocked")
        self.assertIn("command failed", result.blocker)
        self.assertIn("status=blocked", evidence)

    def test_reentry_into_existing_clone_skips_sparse_checkout(self) -> None:
        calls: list[tuple[str, ...]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            lab_root = Path(temp_dir)
            existing = lab_root / "assets" / "phase3-mbptl"
            (existing / ".git").mkdir(parents=True)
            with patch("primordial.labs.ctf.asset_setup.shutil.which", return_value="/usr/bin/tool"):
                result = setup_phase_assets(3, lab_root=lab_root, command_runner=_runner(calls))[0]

        self.assertEqual(result.status, "asset_ready")
        self.assertTrue(any(call[-1] == "--is-inside-work-tree" for call in calls))
        self.assertFalse(any("sparse-checkout" in " ".join(call) for call in calls))

    def test_phase_four_full_clone_still_removes_denied_solutions_path(self) -> None:
        calls: list[tuple[str, ...]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("primordial.labs.ctf.asset_setup.shutil.which", return_value="/usr/bin/tool"):
                result = setup_phase_assets(4, lab_root=Path(temp_dir), command_runner=_runner(calls))[0]
            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(result.status, "asset_ready")
        self.assertFalse(any("sparse-checkout" in " ".join(call) for call in calls))
        self.assertIn("denied_path_removed=solutions/", evidence)
        self.assertFalse((Path(result.asset_path) / "solutions").exists())

    def test_phase_seven_clones_official_cloudgoat_reference_for_localstack_adaptation(self) -> None:
        calls: list[tuple[str, ...]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("primordial.labs.ctf.asset_setup.shutil.which", return_value="/usr/bin/tool"):
                result = setup_phase_assets(7, lab_root=Path(temp_dir), command_runner=_runner(calls))[0]
            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        clone = next(command for command in calls if command[:2] == ("git", "clone"))
        self.assertEqual(result.status, "asset_ready")
        self.assertEqual(result.lab_id, "cloudgoat")
        self.assertEqual(clone[-2], "https://github.com/RhinoSecurityLabs/cloudgoat.git")
        self.assertIn("provisioning_note=CloudGoat is cloned as the official scenario reference", evidence)
        self.assertIn("tool_aws.returncode=0", evidence)
        self.assertIn("denied_path_removed=solutions/", evidence)

    def test_phase_eight_nyu_uses_sparse_checkout_and_removes_nested_denied_material(self) -> None:
        calls: list[tuple[str, ...]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("primordial.labs.ctf.asset_setup.shutil.which", return_value="/usr/bin/tool"):
                results = setup_phase_assets(8, lab_root=Path(temp_dir), command_runner=_runner(calls))
            result = results[-1]
            asset_path = Path(result.asset_path)
            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        clone = next(command for command in calls if command[-2] == "https://github.com/NYU-LLM-CTF/NYU_CTF_Bench.git")
        sparse_set = next(command for command in calls if command[:5] == ("git", "-C", result.asset_path, "sparse-checkout", "set"))
        self.assertEqual(result.status, "asset_ready")
        self.assertIn("--no-checkout", clone)
        self.assertIn("test/2017/CSAW-Quals/web/littlequery", sparse_set)
        self.assertIn("denied_name_pattern=*solution*", evidence)
        self.assertIn("denied_path_removed=nested/solution.py", evidence)
        self.assertIn("denied_path_removed=hints", evidence)
        self.assertFalse((asset_path / "nested" / "solution.py").exists())
        self.assertFalse((asset_path / "hints").exists())


def _runner(calls: list[tuple[str, ...]]):
    def run(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[:2] == ("git", "clone"):
            asset_dir = Path(command[-1])
            asset_dir.mkdir(parents=True, exist_ok=True)
            (asset_dir / ".git").mkdir(exist_ok=True)
            (asset_dir / "writeup").mkdir(exist_ok=True)
            (asset_dir / "solutions").mkdir(exist_ok=True)
            (asset_dir / "nested").mkdir(exist_ok=True)
            (asset_dir / "nested" / "solution.py").write_text("solution", encoding="utf-8")
            (asset_dir / "hints").mkdir(exist_ok=True)
            (asset_dir / "solve.txt").write_text("solution", encoding="utf-8")
        stdout = "true" if command[-1] == "--is-inside-work-tree" else "0123456789abcdef\n"
        return subprocess.CompletedProcess(command, 0, stdout, "")

    return run


def _failing_clone_runner():
    def run(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        if command[:2] == ("git", "clone"):
            return subprocess.CompletedProcess(command, 1, "", "fatal: clone failed")
        return subprocess.CompletedProcess(command, 0, "0123456789abcdef\n", "")

    return run


if __name__ == "__main__":
    unittest.main()
