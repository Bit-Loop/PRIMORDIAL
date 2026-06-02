from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from primordial.labs.ctf.live_runner import run_all, run_autonomous_attempt, run_phase
from tests.support import fixture_flag


class CTFLiveRunnerTests(unittest.TestCase):
    def test_phase_zero_runner_starts_local_harness_without_raw_flag_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_phase(
                0,
                lab_root=Path(temp_dir),
                command_runner=_runner(),
                http_getter=lambda _url: b"phase zero harness",
                timeout_seconds=0.01,
            )

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")
            raw_flag = (Path(temp_dir) / "runtime/phase0-harness/site/flag.txt").read_text(encoding="utf-8").strip()

        self.assertEqual(result.status, "ready")
        self.assertEqual(result.lab_id, "local-harness")
        self.assertEqual(result.target_url, "http://127.0.0.1:3090/")
        self.assertTrue(raw_flag.startswith("ctf{phase0-"))
        self.assertIn("harness=python-http-local", evidence)
        self.assertIn("flag_value_sha256=", evidence)
        self.assertIn("flag_value_redacted=true", evidence)
        self.assertIn("http.body_sha256=", evidence)
        self.assertNotIn(raw_flag, evidence)

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
        self.assertEqual(result.target_url, "http://127.0.0.1:3100/")
        self.assertTrue(result.evidence_ref.startswith("evidence:live-lab:"))
        self.assertIn("completion_indicator=autonomous_flags", evidence)
        self.assertIn("readiness_only=true", evidence)
        self.assertIn("http.body_sha256=", evidence)
        self.assertIn("docker_run.returncode=0", evidence)
        self.assertNotIn("healthy lab body", evidence)
        self.assertNotIn(fixture_flag(), evidence)

    def test_phase_two_runner_mounts_generated_flag_without_raw_flag_evidence(self) -> None:
        calls: list[tuple[str, ...]] = []
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_phase(
                2,
                lab_root=Path(temp_dir),
                command_runner=_runner(calls=calls),
                http_getter=lambda _url: b"vulnerable apache lab",
                timeout_seconds=0.01,
            )

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")
            raw_flag = (
                Path(temp_dir) / "runtime/phase2-vulhub-httpd-cve-2021-41773/primordial_flag.txt"
            ).read_text(encoding="utf-8").strip()

        docker_run = next(command for command in calls if command[:2] == ("docker", "run"))
        self.assertEqual(result.status, "ready")
        self.assertEqual(result.lab_id, "vulhub-httpd-cve-2021-41773")
        self.assertTrue(raw_flag.startswith("ctf{phase2-"))
        self.assertIn("vulnerability_cve_id=CVE-2021-41773", evidence)
        self.assertIn("flag_mount_container_path=/primordial_flag.txt", evidence)
        self.assertIn("flag_value_sha256=", evidence)
        self.assertIn("flag_value_redacted=true", evidence)
        self.assertIn("/primordial_flag.txt:ro", " ".join(docker_run))
        self.assertNotIn(raw_flag, evidence)

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
        self.assertEqual(result.target_url, "http://127.0.0.1:4566/")
        self.assertIn("completion_indicator=autonomous_flags", evidence)
        self.assertIn("readiness_only=true", evidence)
        self.assertIn("upstream_lab=https://github.com/rhinosecuritylabs/cloudgoat", evidence)
        self.assertIn("localstack_sts.stdout_sha256=", evidence)
        self.assertNotIn("000000000000", evidence)

    def test_unsupported_phases_record_concrete_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_phase(99, lab_root=Path(temp_dir), command_runner=_runner())

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")

        self.assertEqual(result.status, "blocked")
        self.assertIn("not configured", result.blocker)
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

    def test_phase_six_runner_records_goad_provider_preflight_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lab_root = Path(temp_dir)
            goad_py = lab_root / "assets/phase6-goad/goad.py"
            goad_py.parent.mkdir(parents=True)
            goad_py.write_text("print('check')\n", encoding="utf-8")

            result = run_phase(
                6,
                lab_root=lab_root,
                command_runner=_goad_runner(),
                timeout_seconds=0.01,
            )

            evidence = Path(result.evidence_path).read_text(encoding="utf-8")
            goad_config = lab_root / "runtime/goad-home/.goad/goad.ini"
            goad_config_exists = goad_config.is_file()

        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.lab_id, "goad-light")
        self.assertIn("VBoxManage missing", result.blocker)
        self.assertIn("vagrant-vbguest plugin missing", result.blocker)
        self.assertIn("GOAD Ansible collections missing", result.blocker)
        self.assertIn("GOAD-Light instance not provisioned", result.blocker)
        self.assertTrue(goad_config_exists)
        self.assertIn("readiness_scope=provider_preflight", evidence)
        self.assertIn("goad_config_sha256=", evidence)
        self.assertIn("goad_check.stdout_sha256=", evidence)
        self.assertNotIn("Missing ansible-galaxy collection", evidence)
        self.assertNotIn("No instance found", evidence)

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
            override_text = override.read_text(encoding="utf-8")

        self.assertEqual(result.status, "ready")
        self.assertEqual(result.lab_id, "cicd-goat")
        self.assertEqual(result.target_url, "http://127.0.0.1:38000/")
        self.assertTrue(override_exists)
        self.assertIn("override_sha256=", evidence)
        self.assertIn("jenkins_url=http://127.0.0.1:38080/", evidence)
        self.assertIn("gitlab_url=http://127.0.0.1:34000/", evidence)
        self.assertIn("docker_compose_up.returncode=0", evidence)
        self.assertIn("http.body_sha256=", evidence)
        self.assertIn("cleanup_deferred=true", evidence)
        self.assertIn("127.0.0.1:35150:5050", override_text)
        self.assertNotIn("127.0.0.1:35050:5050", override_text)
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
        self.assertEqual([result.status for result in results if result.phase in {0, 1, 2, 5, 7}], ["ready"] * 5)

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
        metadata = json.loads(calls[1][calls[1].index("--metadata-json") + 1])
        self.assertTrue(metadata["local_ctf_autonomous"])
        self.assertEqual(metadata["ctf_completion_indicator"], "autonomous_flags")
        self.assertEqual(metadata["ctf_target_url"], "http://127.0.0.1:3100/")
        self.assertEqual(metadata["writeup_access_policy"], "closed_book")
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

    def test_autonomous_attempt_records_benchmark_ref_without_marking_solved(self) -> None:
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
                command_runner=_attempt_runner(stdout="benchmark_solve_ref=evidence:benchmark-solve-redacted\n"),
            )

            evidence = Path(attempt.evidence_path).read_text(encoding="utf-8")
            session = Path(attempt.solve_session_path).read_text(encoding="utf-8")

        self.assertEqual(attempt.status, "attempted")
        self.assertEqual(attempt.solve_status, "attempted")
        self.assertEqual(attempt.benchmark_solve_ref, "evidence:benchmark-solve-redacted")
        self.assertEqual(attempt.captured_flag_ref, "")
        self.assertIn("benchmark_solve_ref=evidence:benchmark-solve-redacted", evidence)
        self.assertIn("captured_flag_ref=", evidence)
        self.assertIn("primordial_autonomous_benchmark_solve", session)
        self.assertIn('"solve_status": "attempted"', session)

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


def _runner(stdout: str = "ok", calls: list[tuple[str, ...]] | None = None):
    def run(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        if calls is not None:
            calls.append(command)
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


def _goad_runner():
    def run(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        if command[:2] == ("vagrant", "version"):
            return subprocess.CompletedProcess(command, 0, "Installed Version: 2.4.9\n", "")
        if command[:3] == ("vagrant", "plugin", "list"):
            return subprocess.CompletedProcess(command, 0, "vagrant-reload (0.0.1)\n", "")
        if command[:2] == ("VBoxManage", "--version"):
            return subprocess.CompletedProcess(command, 127, "", "not found")
        if command[:3] == ("docker", "image", "inspect"):
            return subprocess.CompletedProcess(command, 0, "[]", "")
        if command[:2] == ("python3", "goad.py"):
            return subprocess.CompletedProcess(command, 0, "No instance found\nMissing ansible-galaxy collection community.general\n", "")
        return subprocess.CompletedProcess(command, 0, "ok", "")

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
