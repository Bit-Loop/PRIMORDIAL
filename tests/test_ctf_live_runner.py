from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from primordial.labs.ctf.live_runner import run_all, run_autonomous_attempt, run_phase
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

    def test_phase_runner_can_defer_cleanup_while_autonomous_attempt_uses_live_lab(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_phase(
                1,
                lab_root=Path(temp_dir),
                command_runner=_runner(),
                http_getter=lambda _url: b"ready",
                timeout_seconds=0.01,
                keep_running=True,
            )

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(result.status, "ready")
        self.assertIn("cleanup_deferred=true", evidence)
        self.assertNotIn("docker_rm.returncode=", evidence)

    def test_autonomous_attempt_runs_primordial_cli_and_records_no_solve_without_flag_ref(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            readiness = run_phase(
                1,
                lab_root=Path(temp_dir),
                command_runner=_runner(),
                http_getter=lambda _url: b"ready",
                timeout_seconds=0.01,
            )
            calls: list[tuple[str, ...]] = []

            attempt = run_autonomous_attempt(
                readiness,
                lab_root=Path(temp_dir),
                command_runner=_attempt_runner(calls=calls),
                cycles=2,
                max_executions=1,
            )

            evidence = Path(attempt.evidence_path).read_text(encoding="utf-8")
            session = Path(attempt.solve_session_path).read_text(encoding="utf-8")

        self.assertEqual(attempt.status, "attempted")
        self.assertEqual(attempt.solve_status, "attempted")
        self.assertEqual(calls[0][:3], ("python3", "-m", "primordial.cli"))
        self.assertIn("primordial_command_1.stdout_sha256=", evidence)
        self.assertIn("completion_indicator=autonomous_flags", evidence)
        self.assertNotIn("Dashboard", evidence)
        self.assertIn('"active_intent": "ctf_solve_autonomous_local"', session)

    def test_autonomous_attempt_marks_solved_only_from_redacted_flag_evidence_ref(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            readiness = run_phase(
                1,
                lab_root=Path(temp_dir),
                command_runner=_runner(),
                http_getter=lambda _url: b"ready",
                timeout_seconds=0.01,
            )
            raw_flag = fixture_flag("autonomous-solve")
            attempt = run_autonomous_attempt(
                readiness,
                lab_root=Path(temp_dir),
                command_runner=_attempt_runner(stdout=f"captured_flag_ref=evidence:captured-flag-redacted\n{raw_flag}"),
            )

            evidence = Path(attempt.evidence_path).read_text(encoding="utf-8")
            session = Path(attempt.solve_session_path).read_text(encoding="utf-8")

        self.assertEqual(attempt.status, "solved")
        self.assertEqual(attempt.captured_flag_ref, "evidence:captured-flag-redacted")
        self.assertIn("captured_flag_ref=evidence:captured-flag-redacted", evidence)
        self.assertIn('"solve_status": "solved"', session)
        self.assertNotIn(raw_flag, evidence)
        self.assertNotIn(raw_flag, session)

    def test_autonomous_attempt_blocks_when_primordial_runtime_cannot_start(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            readiness = run_phase(
                1,
                lab_root=Path(temp_dir),
                command_runner=_runner(),
                http_getter=lambda _url: b"ready",
                timeout_seconds=0.01,
            )
            attempt = run_autonomous_attempt(
                readiness,
                lab_root=Path(temp_dir),
                command_runner=_attempt_runner(returncode=1, stderr="PRIMORDIAL_DATABASE_URL is required"),
            )

            evidence = Path(attempt.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(attempt.status, "blocked")
        self.assertIn("primordial command 1 failed", attempt.blocker)
        self.assertIn("primordial_command_1.stderr_sha256=", evidence)
        self.assertNotIn("PRIMORDIAL_DATABASE_URL is required", evidence)


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


def _attempt_runner(
    *,
    calls: list[tuple[str, ...]] | None = None,
    stdout: str = "Dashboard",
    stderr: str = "",
    returncode: int = 0,
):
    def run(command: tuple[str, ...], env: object) -> subprocess.CompletedProcess[str]:
        if calls is not None:
            calls.append(command)
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)

    return run


if __name__ == "__main__":
    unittest.main()
