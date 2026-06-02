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
            result = run_phase(6, lab_root=Path(temp_dir), command_runner=_runner())

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(result.status, "blocked")
        self.assertIn("GOAD", result.blocker)
        self.assertIn("blocker=", evidence)

    def test_phase_five_runner_hashes_kubernetes_goat_cluster_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_phase(
                5,
                lab_root=Path(temp_dir),
                command_runner=_runner(stdout='{"items":[{"metadata":{"name":"pod"}}]}'),
                timeout_seconds=0.01,
            )

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(result.status, "ready")
        self.assertEqual(result.lab_id, "kubernetes-goat")
        self.assertIn("cluster=kind-primordial-k8s", evidence)
        self.assertIn("kubectl_nodes.stdout_sha256=", evidence)
        self.assertIn("kubectl_wait_deployments.stdout_sha256=", evidence)
        self.assertIn("kubectl_pods.stdout_sha256=", evidence)
        self.assertNotIn("metadata", evidence)

    def test_phase_three_runner_starts_mbptl_compose_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lab_root = Path(temp_dir)
            compose_file = lab_root / "assets/phase3-mbptl/mbptl/docker-compose.yml"
            compose_file.parent.mkdir(parents=True)
            compose_file.write_text("services:\n  main:\n    image: local\n", encoding="utf-8")

            result = run_phase(
                3,
                lab_root=lab_root,
                command_runner=_runner(stdout='{"Service":"main","State":"running"}'),
                http_getter=lambda _url: b"mbptl ready body",
                timeout_seconds=0.01,
                keep_running=True,
            )

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(result.status, "ready")
        self.assertEqual(result.lab_id, "mbptl")
        self.assertEqual(result.target_url, "http://127.0.0.1:3183/")
        self.assertIn("upstream_lab=https://github.com/bayufedra/MBPTL", evidence)
        self.assertIn("docker_compose_up.returncode=0", evidence)
        self.assertIn("http.body_sha256=", evidence)
        self.assertIn("cleanup_deferred=true", evidence)
        self.assertNotIn("mbptl ready body", evidence)

    def test_phase_four_runner_starts_cicd_goat_with_local_port_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lab_root = Path(temp_dir)
            compose_file = lab_root / "assets/phase4-cicd-goat/docker-compose.yaml"
            compose_file.parent.mkdir(parents=True)
            compose_file.write_text("services:\n  ctfd:\n    image: local\n", encoding="utf-8")

            result = run_phase(
                4,
                lab_root=lab_root,
                command_runner=_runner(stdout='{"Service":"ctfd","State":"running"}'),
                http_getter=lambda _url: b"cicd goat ready body",
                timeout_seconds=0.01,
                keep_running=True,
            )

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")
            override = lab_root / "runtime/phase4-cicd-goat-port-override.yml"
            override_exists = override.is_file()

        self.assertEqual(result.status, "ready")
        self.assertEqual(result.lab_id, "cicd-goat")
        self.assertEqual(result.target_url, "http://127.0.0.1:38000/")
        self.assertTrue(override_exists)
        self.assertIn("override_sha256=", evidence)
        self.assertIn("docker_compose_up.returncode=0", evidence)
        self.assertIn("http.body_sha256=", evidence)
        self.assertIn("cleanup_deferred=true", evidence)
        self.assertNotIn("cicd goat ready body", evidence)

    def test_phase_eight_runner_starts_nyu_littlequery_compose_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lab_root = Path(temp_dir)
            compose_file = lab_root / "assets/phase8-nyu-ctf-bench/test/2017/CSAW-Quals/web/littlequery/docker-compose.yml"
            compose_file.parent.mkdir(parents=True)
            compose_file.write_text("services:\n  littlequery:\n    image: local\n", encoding="utf-8")

            result = run_phase(
                8,
                lab_root=lab_root,
                command_runner=_runner(stdout='{"State":"running"}'),
                http_getter=lambda _url: b"nyu littlequery ready",
                timeout_seconds=0.01,
                keep_running=True,
            )

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(result.status, "ready")
        self.assertEqual(result.lab_id, "nyu-ctf-bench-littlequery")
        self.assertEqual(result.target_url, "http://127.0.0.1:8080/")
        self.assertIn("challenge_path=test/2017/CSAW-Quals/web/littlequery", evidence)
        self.assertIn("docker_compose_up.returncode=0", evidence)
        self.assertIn("docker_inspect_target.stdout_sha256=", evidence)
        self.assertIn("cleanup_deferred=true", evidence)
        self.assertNotIn("nyu littlequery ready", evidence)

    def test_run_all_includes_every_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            results = run_all(
                lab_root=Path(temp_dir),
                command_runner=_runner(),
                http_getter=lambda _url: b"ok",
                timeout_seconds=0.01,
            )

        self.assertEqual([result.phase for result in results], list(range(9)))
        self.assertEqual([result.status for result in results if result.phase in {1, 2, 5, 7}], ["ready"] * 4)

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
        elif command[:3] == ("docker", "network", "create"):
            selected_stdout = "network-id"
        elif command[:2] == ("docker", "compose"):
            selected_stdout = stdout
        elif command[:2] == ("docker", "run"):
            selected_stdout = "container-id"
        elif command[:3] == ("docker", "inspect", "primordial-nyu-littlequery-littlequery-1"):
            selected_stdout = "http://127.0.0.1:8080/"
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
