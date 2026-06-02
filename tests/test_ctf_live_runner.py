from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from primordial.labs.ctf.live_runner import run_all, run_phase
from tests.support import fixture_flag


class CTFLiveRunnerTests(unittest.TestCase):
    def test_phase_one_runner_writes_hashed_http_evidence_without_raw_body(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_phase(
                1,
                lab_root=Path(temp_dir),
                command_runner=_runner(),
                http_getter=lambda _url: b"healthy lab body " + fixture_flag().encode("utf-8"),
                timeout_seconds=0.01,
            )

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(result.status, "ready")
        self.assertEqual(result.lab_id, "juice-shop")
        self.assertTrue(result.evidence_ref.startswith("evidence:live-lab:"))
        self.assertIn("completion_indicator=autonomous_flags", evidence)
        self.assertIn("readiness_only=true", evidence)
        self.assertIn("http.body_sha256=", evidence)
        self.assertIn("docker_run.returncode=0", evidence)
        self.assertNotIn("healthy lab body", evidence)
        self.assertNotIn(fixture_flag(), evidence)

    def test_phase_seven_runner_uses_localstack_and_hashes_cli_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_phase(
                7,
                lab_root=Path(temp_dir),
                command_runner=_runner(stdout='{"Account":"000000000000"}'),
                http_getter=lambda _url: b'{"services":{"sts":"running"}}',
                timeout_seconds=0.01,
            )

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(result.status, "ready")
        self.assertEqual(result.lab_id, "cloudgoat-localstack-adaptation")
        self.assertIn("completion_indicator=autonomous_flags", evidence)
        self.assertIn("readiness_only=true", evidence)
        self.assertIn("upstream_lab=https://github.com/RhinoSecurityLabs/cloudgoat", evidence)
        self.assertIn("localstack_sts.stdout_sha256=", evidence)
        self.assertNotIn("000000000000", evidence)

    def test_unsupported_phases_record_concrete_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_phase(5, lab_root=Path(temp_dir), command_runner=_runner())

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(result.status, "blocked")
        self.assertIn("Kubernetes Goat", result.blocker)
        self.assertIn("blocker=", evidence)

    def test_run_all_includes_every_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            results = run_all(
                lab_root=Path(temp_dir),
                command_runner=_runner(),
                http_getter=lambda _url: b"ok",
                timeout_seconds=0.01,
            )

        self.assertEqual([result.phase for result in results], list(range(9)))
        self.assertEqual([result.status for result in results if result.phase in {1, 2, 7}], ["ready"] * 3)


def _runner(stdout: str = "ok"):
    def run(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        if command[:3] == ("docker", "rm", "-f"):
            selected_stdout = command[-1]
        elif command[:2] == ("docker", "run"):
            selected_stdout = "container-id"
        elif command[:2] == ("docker", "inspect"):
            selected_stdout = "container-id running image:tag"
        else:
            selected_stdout = stdout
        return subprocess.CompletedProcess(command, 0, selected_stdout, "")

    return run


if __name__ == "__main__":
    unittest.main()
