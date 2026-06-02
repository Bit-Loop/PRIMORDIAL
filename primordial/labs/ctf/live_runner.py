from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from dataclasses import dataclass
from datetime import UTC, datetime
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Mapping
from urllib.error import URLError
from urllib.request import urlopen

from primordial.labs.ctf.sessions import SolveSession

DEFAULT_LAB_ROOT = Path("/run/media/bitloop/DREAD/primordial-labs")
DEFAULT_KUBERNETES_GOAT_KUBECONFIG = DEFAULT_LAB_ROOT / "kubeconfigs" / "phase5-kind.yaml"
READY_PHASES = frozenset({1, 2, 5, 7})

CommandRunner = Callable[[tuple[str, ...]], subprocess.CompletedProcess[str]]
AttemptCommandRunner = Callable[[tuple[str, ...], Mapping[str, str]], subprocess.CompletedProcess[str]]
HttpGetter = Callable[[str], bytes]


@dataclass(frozen=True, slots=True)
class LiveLabRunResult:
    phase: int
    status: str
    lab_id: str
    evidence_path: str
    evidence_ref: str
    blocker: str = ""

    def as_payload(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "status": self.status,
            "lab_id": self.lab_id,
            "evidence_path": self.evidence_path,
            "evidence_ref": self.evidence_ref,
            "blocker": self.blocker,
        }


@dataclass(frozen=True, slots=True)
class AutonomousAttemptResult:
    phase: int
    status: str
    lab_id: str
    solve_status: str
    evidence_path: str
    evidence_ref: str
    solve_session_path: str
    captured_flag_ref: str = ""
    blocker: str = ""

    def as_payload(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "status": self.status,
            "lab_id": self.lab_id,
            "solve_status": self.solve_status,
            "evidence_path": self.evidence_path,
            "evidence_ref": self.evidence_ref,
            "solve_session_path": self.solve_session_path,
            "captured_flag_ref": self.captured_flag_ref,
            "blocker": self.blocker,
        }


def run_phase(
    phase: int,
    *,
    lab_root: Path = DEFAULT_LAB_ROOT,
    command_runner: CommandRunner | None = None,
    http_getter: HttpGetter | None = None,
    timeout_seconds: float = 90.0,
    keep_running: bool = False,
) -> LiveLabRunResult:
    if phase == 1:
        return _run_docker_http_lab(
            phase=1,
            lab_id="juice-shop",
            image="bkimminich/juice-shop:latest",
            container_name="primordial-live-juice",
            host_port=3100,
            container_port=3000,
            lab_root=lab_root,
            command_runner=command_runner,
            http_getter=http_getter,
            timeout_seconds=timeout_seconds,
            keep_running=keep_running,
        )
    if phase == 2:
        return _run_docker_http_lab(
            phase=2,
            lab_id="vulhub-httpd-cve-2021-41773",
            image="primordial-vulhub-httpd-cve-2021-41773:proof",
            container_name="primordial-live-vulhub-httpd",
            host_port=3180,
            container_port=80,
            lab_root=lab_root,
            command_runner=command_runner,
            http_getter=http_getter,
            timeout_seconds=timeout_seconds,
            keep_running=keep_running,
        )
    if phase == 7:
        return _run_localstack_lab(
            lab_root=lab_root,
            command_runner=command_runner,
            http_getter=http_getter,
            timeout_seconds=timeout_seconds,
            keep_running=keep_running,
        )
    if phase == 5:
        return _run_kubernetes_goat_lab(
            lab_root=lab_root,
            command_runner=command_runner,
            kubeconfig=lab_root / "kubeconfigs" / "phase5-kind.yaml",
        )
    return _blocked_phase_result(phase, lab_root=lab_root)


def run_autonomous_attempt(
    readiness: LiveLabRunResult,
    *,
    lab_root: Path = DEFAULT_LAB_ROOT,
    command_runner: AttemptCommandRunner | None = None,
    cycles: int = 3,
    max_executions: int = 3,
    timeout_seconds: float = 300.0,
    cleanup_live_lab: bool = False,
) -> AutonomousAttemptResult:
    phase = readiness.phase
    lab_id = readiness.lab_id
    evidence = _evidence_file(lab_root, phase=phase, lab_id=f"{lab_id}-autonomous-attempt")
    session_path = _evidence_file(lab_root, phase=phase, lab_id=f"{lab_id}-solve-session").with_suffix(".json")
    lines = _evidence_header(phase=phase, lab_id=lab_id) + [
        "attempt_type=primordial_autonomous_local",
        f"readiness_status={readiness.status}",
        f"readiness_evidence_ref={readiness.evidence_ref}",
    ]
    session = _start_solve_session(phase=phase, lab_id=lab_id)
    if readiness.status != "ready":
        blocker = f"readiness is {readiness.status}"
        lines.extend(_cleanup_live_lab_lines(readiness) if cleanup_live_lab else ())
        session = session.record_blocked_action(
            action_id=f"action:phase{phase}:readiness",
            reason=blocker,
            policy_decision_id="policy:local-ctf-autonomous-blocked",
        ).complete(result="no_solve", solve_status="blocked", report_ref=readiness.evidence_ref)
        return _write_attempt_result(
            phase=phase,
            lab_id=lab_id,
            status="blocked",
            solve_status="blocked",
            evidence=evidence,
            session_path=session_path,
            session=session,
            lines=lines + [f"blocker={blocker}"],
            blocker=blocker,
        )

    target_url = _target_url_for_phase(phase)
    lines.append(f"target_url={target_url}")
    session = session.record_policy_decision(
        decision_id="policy:local-ctf-autonomous-allow",
        action="local_ctf_autonomous_attempt",
        decision="allowed",
    ).record_action(
        action_id=f"action:phase{phase}:readiness",
        action_type="local_lab_readiness",
        status="completed",
        evidence_ids=[readiness.evidence_ref],
        metadata={"target_url": target_url},
    )
    command_results: list[subprocess.CompletedProcess[str]] = []
    try:
        commands = _primordial_attempt_commands(lab_id, target_url, cycles=cycles, max_executions=max_executions)
        lines.append(f"command_count={len(commands)}")
        for index, command in enumerate(commands, start=1):
            result = _run_attempt_command(command, command_runner=command_runner, timeout_seconds=timeout_seconds)
            command_results.append(result)
            lines.extend(_attempt_command_lines(index, result))
            if result.returncode != 0:
                raise RuntimeError(f"primordial command {index} failed")
    except Exception as exc:  # noqa: BLE001 - any subprocess or runtime failure must be recorded as a blocker, not raised
        blocker = str(exc)
        lines.append(f"blocker={blocker}")
        lines.extend(_cleanup_live_lab_lines(readiness) if cleanup_live_lab else ())
        session = session.record_blocked_action(
            action_id=f"action:phase{phase}:primordial-attempt",
            reason=blocker,
            policy_decision_id="policy:local-ctf-autonomous-allow",
        ).complete(result="no_solve", solve_status="blocked", report_ref=readiness.evidence_ref)
        return _write_attempt_result(
            phase=phase,
            lab_id=lab_id,
            status="blocked",
            solve_status="blocked",
            evidence=evidence,
            session_path=session_path,
            session=session,
            lines=lines,
            blocker=blocker,
        )

    captured_flag_ref = _captured_flag_ref_from_results(command_results)
    if captured_flag_ref:
        lines.extend(_cleanup_live_lab_lines(readiness) if cleanup_live_lab else ())
        session = session.record_flag_submission(
            challenge_id=lab_id,
            captured_flag_ref=captured_flag_ref,
            policy_decision_id="policy:local-ctf-autonomous-allow",
        ).complete(result="solved", solve_status="solved", report_ref=captured_flag_ref)
        lines.append(f"captured_flag_ref={captured_flag_ref}")
        return _write_attempt_result(
            phase=phase,
            lab_id=lab_id,
            status="solved",
            solve_status="solved",
            evidence=evidence,
            session_path=session_path,
            session=session,
            lines=lines,
            captured_flag_ref=captured_flag_ref,
        )

    lines.extend(_cleanup_live_lab_lines(readiness) if cleanup_live_lab else ())
    session = session.record_action(
        action_id=f"action:phase{phase}:primordial-attempt",
        action_type="primordial_autonomous_attempt",
        status="completed_no_flag",
        evidence_ids=[readiness.evidence_ref],
        metadata={"command_count": len(command_results)},
    ).complete(result="no_solve", solve_status="attempted", report_ref=readiness.evidence_ref)
    return _write_attempt_result(
        phase=phase,
        lab_id=lab_id,
        status="attempted",
        solve_status="attempted",
        evidence=evidence,
        session_path=session_path,
        session=session,
        lines=lines + ["captured_flag_ref="],
    )


def run_all(
    *,
    lab_root: Path = DEFAULT_LAB_ROOT,
    command_runner: CommandRunner | None = None,
    http_getter: HttpGetter | None = None,
    timeout_seconds: float = 90.0,
) -> tuple[LiveLabRunResult, ...]:
    return tuple(
        run_phase(
            phase,
            lab_root=lab_root,
            command_runner=command_runner,
            http_getter=http_getter,
            timeout_seconds=timeout_seconds,
        )
        for phase in range(9)
    )


def _run_docker_http_lab(
    *,
    phase: int,
    lab_id: str,
    image: str,
    container_name: str,
    host_port: int,
    container_port: int,
    lab_root: Path,
    command_runner: CommandRunner | None,
    http_getter: HttpGetter | None,
    timeout_seconds: float,
    keep_running: bool,
) -> LiveLabRunResult:
    evidence = _evidence_file(lab_root, phase=phase, lab_id=lab_id)
    url = f"http://127.0.0.1:{host_port}/"
    lines = _evidence_header(phase=phase, lab_id=lab_id)
    status = "blocked"
    started = False
    _run(("docker", "rm", "-f", container_name), command_runner=command_runner, check=False)
    try:
        run = _run(
            (
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                container_name,
                "-p",
                f"127.0.0.1:{host_port}:{container_port}",
                image,
            ),
            command_runner=command_runner,
        )
        started = True
        lines.extend(_command_lines("docker_run", run))
        body = _wait_http(url, timeout_seconds=timeout_seconds, http_getter=http_getter)
        lines.extend(_http_lines(url, body))
        inspect = _run(
            ("docker", "inspect", container_name, "--format", "{{.Id}} {{.State.Status}} {{.Config.Image}}"),
            command_runner=command_runner,
        )
        lines.extend(_command_lines("docker_inspect", inspect))
        status = "ready"
        blocker = ""
    except Exception as exc:  # noqa: BLE001 - lab probe records any failure as a blocker rather than crashing
        status = "blocked"
        blocker = str(exc)
        lines.append(f"blocker={blocker}")
    finally:
        if keep_running and started and status == "ready":
            lines.append("cleanup_deferred=true")
        else:
            removed = _run(("docker", "rm", "-f", container_name), command_runner=command_runner, check=False)
            lines.extend(_command_lines("docker_rm", removed))
    return _write_result(phase=phase, status=status, lab_id=lab_id, evidence=evidence, lines=lines, blocker=blocker)


def _run_localstack_lab(
    *,
    lab_root: Path,
    command_runner: CommandRunner | None,
    http_getter: HttpGetter | None,
    timeout_seconds: float,
    keep_running: bool,
) -> LiveLabRunResult:
    phase = 7
    lab_id = "cloudgoat-localstack-adaptation"
    evidence = _evidence_file(lab_root, phase=phase, lab_id=lab_id)
    container_name = "primordial-live-localstack"
    url = "http://127.0.0.1:4566/_localstack/health"
    lines = _evidence_header(phase=phase, lab_id=lab_id) + [
        "upstream_lab=https://github.com/RhinoSecurityLabs/cloudgoat",
    ]
    status = "blocked"
    started = False
    _run(("docker", "rm", "-f", container_name), command_runner=command_runner, check=False)
    try:
        run = _run(
            (
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                container_name,
                "-p",
                "127.0.0.1:4566:4566",
                "-e",
                "SERVICES=sts,s3",
                "localstack/localstack:3.0.2",
            ),
            command_runner=command_runner,
        )
        started = True
        lines.extend(_command_lines("docker_run", run))
        body = _wait_http(url, timeout_seconds=timeout_seconds, http_getter=http_getter)
        lines.extend(_http_lines(url, body))
        sts = _run(
            (
                "aws",
                "--endpoint-url",
                "http://127.0.0.1:4566",
                "sts",
                "get-caller-identity",
            ),
            command_runner=command_runner,
            env={
                "AWS_ACCESS_KEY_ID": "test",
                "AWS_SECRET_ACCESS_KEY": "test",
                "AWS_DEFAULT_REGION": "us-east-1",
            },
        )
        lines.extend(_command_lines("localstack_sts", sts))
        status = "ready"
        blocker = ""
    except Exception as exc:  # noqa: BLE001 - lab probe records any failure as a blocker rather than crashing
        status = "blocked"
        blocker = str(exc)
        lines.append(f"blocker={blocker}")
    finally:
        if keep_running and started and status == "ready":
            lines.append("cleanup_deferred=true")
        else:
            removed = _run(("docker", "rm", "-f", container_name), command_runner=command_runner, check=False)
            lines.extend(_command_lines("docker_rm", removed))
    return _write_result(phase=phase, status=status, lab_id=lab_id, evidence=evidence, lines=lines, blocker=blocker)


def _run_kubernetes_goat_lab(
    *,
    lab_root: Path,
    command_runner: CommandRunner | None,
    kubeconfig: Path = DEFAULT_KUBERNETES_GOAT_KUBECONFIG,
) -> LiveLabRunResult:
    phase = 5
    lab_id = "kubernetes-goat"
    evidence = _evidence_file(lab_root, phase=phase, lab_id=lab_id)
    lines = _evidence_header(phase=phase, lab_id=lab_id) + [
        "cluster=kind-primordial-k8s",
        f"kubeconfig={kubeconfig}",
    ]
    env = {"KUBECONFIG": str(kubeconfig)}
    try:
        node = _run(("kubectl", "--kubeconfig", str(kubeconfig), "get", "nodes", "-o", "json"), command_runner=command_runner, env=env)
        lines.extend(_command_lines("kubectl_nodes", node))
        wait = _run(
            (
                "kubectl",
                "--kubeconfig",
                str(kubeconfig),
                "wait",
                "--for=condition=available",
                "--timeout=60s",
                "deployment",
                "--all",
                "-A",
            ),
            command_runner=command_runner,
            env=env,
        )
        lines.extend(_command_lines("kubectl_wait_deployments", wait))
        pods = _run(("kubectl", "--kubeconfig", str(kubeconfig), "get", "pods", "-A", "-o", "json"), command_runner=command_runner, env=env)
        lines.extend(_command_lines("kubectl_pods", pods))
        status = "ready"
        blocker = ""
    except Exception as exc:  # noqa: BLE001 - live cluster readiness failures must be recorded as blockers
        status = "blocked"
        blocker = str(exc)
        lines.append(f"blocker={blocker}")
    return _write_result(phase=phase, status=status, lab_id=lab_id, evidence=evidence, lines=lines, blocker=blocker)


def _blocked_phase_result(phase: int, *, lab_root: Path) -> LiveLabRunResult:
    blockers = {
        0: "Phase 0 is harness/source validation only; use the CTF unit and hardcode gates.",
        3: "MBPTL local lab checkout/provisioning assets are not present yet.",
        4: "CI/CD Goat compose checkout is not present yet.",
        5: "Kubernetes Goat requires local kubectl/kind/helm tooling and lab checkout.",
        6: "GOAD-Light/GOAD requires local VM/lab provisioning assets.",
        8: "DreadGOAD/CTF-Dojo/NYU CTF Bench local benchmark assets are not present yet.",
    }
    lab_id = f"phase-{phase}-blocked"
    evidence = _evidence_file(lab_root, phase=phase, lab_id=lab_id)
    blocker = blockers.get(phase, "Phase is not configured for local live runner yet.")
    lines = _evidence_header(phase=phase, lab_id=lab_id) + [f"blocker={blocker}"]
    return _write_result(phase=phase, status="blocked", lab_id=lab_id, evidence=evidence, lines=lines, blocker=blocker)


def _run(
    command: tuple[str, ...],
    *,
    command_runner: CommandRunner | None,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    if command_runner is None:
        selected_env = {**os.environ, **(env or {})}
        completed = subprocess.run(command, check=False, capture_output=True, text=True, env=selected_env)
    else:
        completed = command_runner(command)
    if check and completed.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(command)}")
    return completed


def _run_attempt_command(
    command: tuple[str, ...],
    *,
    command_runner: AttemptCommandRunner | None,
    timeout_seconds: float,
) -> subprocess.CompletedProcess[str]:
    env = _primordial_attempt_env()
    if command_runner is not None:
        return command_runner(command, env)
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, **env},
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            command,
            124,
            exc.stdout if isinstance(exc.stdout, str) else "",
            exc.stderr if isinstance(exc.stderr, str) else "timeout expired",
        )


def _cleanup_live_lab_lines(readiness: LiveLabRunResult) -> list[str]:
    command = _cleanup_command_for_phase(readiness.phase)
    if not command:
        return ["cleanup.skipped=true"]
    result = _run(command, command_runner=None, check=False)
    return [
        "cleanup.skipped=false",
        *_command_lines("cleanup", result),
    ]


def _cleanup_command_for_phase(phase: int) -> tuple[str, ...]:
    containers = {
        1: "primordial-live-juice",
        2: "primordial-live-vulhub-httpd",
        7: "primordial-live-localstack",
    }
    container = containers.get(phase)
    return ("docker", "rm", "-f", container) if container else ()


def _wait_http(url: str, *, timeout_seconds: float, http_getter: HttpGetter | None) -> bytes:
    deadline = time.monotonic() + timeout_seconds
    last_error = ""
    while time.monotonic() < deadline:
        try:
            return _http_get(url, http_getter=http_getter)
        except (OSError, URLError) as exc:
            last_error = str(exc)
            time.sleep(1)
    raise RuntimeError(f"HTTP probe did not become healthy: {url} {last_error}".strip())


def _http_get(url: str, *, http_getter: HttpGetter | None) -> bytes:
    if http_getter is not None:
        return http_getter(url)
    with urlopen(url, timeout=5) as response:
        status = int(getattr(response, "status", response.getcode()))
        if status < 200 or status >= 400:
            raise RuntimeError(f"HTTP probe returned {status}: {url}")
        return response.read(4096)


def _evidence_file(lab_root: Path, *, phase: int, lab_id: str) -> Path:
    evidence_dir = lab_root / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    return evidence_dir / f"phase{phase}-{lab_id}.txt"


def _write_result(
    *,
    phase: int,
    status: str,
    lab_id: str,
    evidence: Path,
    lines: list[str],
    blocker: str,
) -> LiveLabRunResult:
    evidence.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    evidence_ref = f"evidence:live-lab:{_sha256_bytes(evidence.read_bytes())[:16]}"
    return LiveLabRunResult(
        phase=phase,
        status=status,
        lab_id=lab_id,
        evidence_path=str(evidence),
        evidence_ref=evidence_ref,
        blocker=blocker,
    )


def _write_attempt_result(
    *,
    phase: int,
    lab_id: str,
    status: str,
    solve_status: str,
    evidence: Path,
    session_path: Path,
    session: SolveSession,
    lines: list[str],
    captured_flag_ref: str = "",
    blocker: str = "",
) -> AutonomousAttemptResult:
    session_path.write_text(json.dumps(asdict(session), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines.extend(
        [
            f"status={status}",
            f"solve_status={solve_status}",
            f"solve_session_path={session_path}",
            f"solve_session_sha256={_sha256_bytes(session_path.read_bytes())}",
        ]
    )
    evidence.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    evidence_ref = f"evidence:autonomous-attempt:{_sha256_bytes(evidence.read_bytes())[:16]}"
    return AutonomousAttemptResult(
        phase=phase,
        status=status,
        lab_id=lab_id,
        solve_status=solve_status,
        evidence_path=str(evidence),
        evidence_ref=evidence_ref,
        solve_session_path=str(session_path),
        captured_flag_ref=captured_flag_ref,
        blocker=blocker,
    )


def _evidence_header(*, phase: int, lab_id: str) -> list[str]:
    return [
        f"created_at={datetime.now(UTC).isoformat()}",
        f"phase={phase}",
        f"lab_id={lab_id}",
        "completion_indicator=autonomous_flags",
        "readiness_only=true",
    ]


def _command_lines(label: str, result: subprocess.CompletedProcess[str]) -> list[str]:
    return [
        f"{label}.returncode={result.returncode}",
        f"{label}.stdout_sha256={_sha256_text(result.stdout or '')}",
        f"{label}.stderr_sha256={_sha256_text(result.stderr or '')}",
        f"{label}.stdout_bytes={len((result.stdout or '').encode('utf-8'))}",
        f"{label}.stderr_bytes={len((result.stderr or '').encode('utf-8'))}",
    ]


def _attempt_command_lines(index: int, result: subprocess.CompletedProcess[str]) -> list[str]:
    return [
        f"primordial_command_{index}.argv_sha256={_sha256_text(' '.join(result.args))}",
        f"primordial_command_{index}.returncode={result.returncode}",
        f"primordial_command_{index}.stdout_sha256={_sha256_text(result.stdout or '')}",
        f"primordial_command_{index}.stderr_sha256={_sha256_text(result.stderr or '')}",
        f"primordial_command_{index}.stdout_bytes={len((result.stdout or '').encode('utf-8'))}",
        f"primordial_command_{index}.stderr_bytes={len((result.stderr or '').encode('utf-8'))}",
    ]


def _http_lines(url: str, body: bytes) -> list[str]:
    return [
        f"http.url={url}",
        f"http.body_sha256={_sha256_bytes(body)}",
        f"http.body_bytes={len(body)}",
    ]


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _start_solve_session(*, phase: int, lab_id: str) -> SolveSession:
    return SolveSession.start(
        id=f"solve-phase{phase}-{lab_id}",
        target_id=lab_id,
        engagement_profile="co_internal_lab",
        active_intent="ctf_solve_autonomous_local",
        policy_version="policy:local-ctf-autonomous-v1",
        code_version=_git_head_ref(),
        model_versions={"solver": "primordial-cli"},
    )


def _primordial_attempt_commands(
    lab_id: str,
    target_url: str,
    *,
    cycles: int,
    max_executions: int,
) -> tuple[tuple[str, ...], ...]:
    return (
        (
            "python3",
            "-m",
            "primordial.cli",
            "start-session",
            "--methodology",
            "htb_lab",
            "--profile",
            "hack_the_box",
            "--title",
            f"CTF lab {lab_id}",
        ),
        (
            "python3",
            "-m",
            "primordial.cli",
            "add-target",
            lab_id,
            "--profile",
            "hack_the_box",
            "--asset",
            target_url,
            "--display-name",
            f"CTF lab {lab_id}",
        ),
        (
            "python3",
            "-m",
            "primordial.cli",
            "run-loop",
            "--cycles",
            str(max(1, cycles)),
            "--max-executions",
            str(max(1, max_executions)),
        ),
    )


def _primordial_attempt_env() -> dict[str, str]:
    return {
        "PRIMORDIAL_AUTONOMY_MODE": "high_autonomy",
        "PRIMORDIAL_ALLOW_EXPLOITATIVE_ACTIONS": "true",
        "PRIMORDIAL_ALLOW_REMOTE_PREMIUM": "false",
        "PRIMORDIAL_CTF_AUTONOMOUS_ATTEMPT": "true",
    }


def _target_url_for_phase(phase: int) -> str:
    urls = {
        1: "http://127.0.0.1:3100/",
        2: "http://127.0.0.1:3180/",
        5: "kubernetes://kind-primordial-k8s",
        7: "http://127.0.0.1:4566/",
    }
    return urls.get(phase, "")


def _captured_flag_ref_from_results(results: list[subprocess.CompletedProcess[str]]) -> str:
    for result in results:
        ref = _captured_flag_ref_from_text(f"{result.stdout or ''}\n{result.stderr or ''}")
        if ref:
            return ref
    return ""


def _captured_flag_ref_from_text(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        ref = _captured_flag_ref_from_json(stripped)
        if ref:
            return ref
        match = re.search(r"\bcaptured_flag_ref\s*[=:]\s*(evidence:[A-Za-z0-9_.:-]+)", stripped)
        if match:
            return match.group(1)
    return ""


def _captured_flag_ref_from_json(text: str) -> str:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return ""
    if isinstance(payload, dict):
        ref = str(payload.get("captured_flag_ref", "")).strip()
        if ref.startswith("evidence:"):
            return ref
    return ""


def _git_head_ref() -> str:
    try:
        result = subprocess.run(
            ("git", "rev-parse", "--short", "HEAD"),
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return "git:unknown"
    head = result.stdout.strip()
    return f"git:{head}" if result.returncode == 0 and head else "git:unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run local PRIMORDIAL CTF lab evidence probes.")
    parser.add_argument("--phase", type=int, choices=range(9), action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--lab-root", default=str(DEFAULT_LAB_ROOT))
    parser.add_argument("--timeout-seconds", type=float, default=90.0)
    parser.add_argument("--attempt-autonomous", action="store_true")
    parser.add_argument("--attempt-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--primordial-cycles", type=int, default=3)
    parser.add_argument("--primordial-max-executions", type=int, default=3)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    phases = tuple(range(9)) if args.all or not args.phase else tuple(args.phase)
    results_list: list[LiveLabRunResult] = []
    attempts_list: list[AutonomousAttemptResult] = []
    for phase in phases:
        result = run_phase(
            phase,
            lab_root=Path(args.lab_root),
            timeout_seconds=args.timeout_seconds,
            keep_running=args.attempt_autonomous,
        )
        results_list.append(result)
        if args.attempt_autonomous:
            attempts_list.append(
                run_autonomous_attempt(
                    result,
                    lab_root=Path(args.lab_root),
                    cycles=args.primordial_cycles,
                    max_executions=args.primordial_max_executions,
                    timeout_seconds=args.attempt_timeout_seconds,
                    cleanup_live_lab=True,
                )
            )
    results = tuple(results_list)
    attempts = tuple(attempts_list)
    attempt_by_phase = {attempt.phase: attempt.as_payload() for attempt in attempts}
    payload = [
        {**result.as_payload(), **({"autonomous_attempt": attempt_by_phase[result.phase]} if result.phase in attempt_by_phase else {})}
        for result in results
    ]
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for result in results:
            blocker = f" blocker={result.blocker}" if result.blocker else ""
            print(f"phase={result.phase} status={result.status} evidence={result.evidence_path}{blocker}")
            if result.phase in attempt_by_phase:
                attempt = attempt_by_phase[result.phase]
                attempt_blocker = f" blocker={attempt['blocker']}" if attempt["blocker"] else ""
                print(
                    f"phase={result.phase} solve_status={attempt['solve_status']} "
                    f"attempt_evidence={attempt['evidence_path']}{attempt_blocker}"
                )
    return 0 if all(result.status == "ready" for result in results if result.phase in READY_PHASES) else 1


if __name__ == "__main__":
    raise SystemExit(main())
