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
        self.assertEqual(calls[0][:5], ("git", "clone", "--filter=blob:none", "--depth", "1"))
        self.assertIn("--no-checkout", calls[0])
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


def _runner(calls: list[tuple[str, ...]]):
    def run(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[:2] == ("git", "clone"):
            asset_dir = Path(command[-1])
            asset_dir.mkdir(parents=True, exist_ok=True)
            (asset_dir / ".git").mkdir(exist_ok=True)
            (asset_dir / "writeup").mkdir(exist_ok=True)
            (asset_dir / "solutions").mkdir(exist_ok=True)
        stdout = "true" if command[-1] == "--is-inside-work-tree" else "0123456789abcdef\n"
        return subprocess.CompletedProcess(command, 0, stdout, "")

    return run


if __name__ == "__main__":
    unittest.main()
