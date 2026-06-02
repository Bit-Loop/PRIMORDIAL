from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from urllib.error import URLError
from urllib.request import urlopen

DEFAULT_LAB_ROOT = Path("/run/media/bitloop/DREAD/primordial-labs")
READY_PHASES = frozenset({1, 2, 7})

CommandRunner = Callable[[tuple[str, ...]], subprocess.CompletedProcess[str]]
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


def run_phase(
    phase: int,
    *,
    lab_root: Path = DEFAULT_LAB_ROOT,
    command_runner: CommandRunner | None = None,
    http_getter: HttpGetter | None = None,
    timeout_seconds: float = 90.0,
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
        )
    if phase == 7:
        return _run_localstack_lab(
            lab_root=lab_root,
            command_runner=command_runner,
            http_getter=http_getter,
            timeout_seconds=timeout_seconds,
        )
    return _blocked_phase_result(phase, lab_root=lab_root)


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
) -> LiveLabRunResult:
    evidence = _evidence_file(lab_root, phase=phase, lab_id=lab_id)
    url = f"http://127.0.0.1:{host_port}/"
    lines = _evidence_header(phase=phase, lab_id=lab_id)
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
    except Exception as exc:
        status = "blocked"
        blocker = str(exc)
        lines.append(f"blocker={blocker}")
    finally:
        removed = _run(("docker", "rm", "-f", container_name), command_runner=command_runner, check=False)
        lines.extend(_command_lines("docker_rm", removed))
    return _write_result(phase=phase, status=status, lab_id=lab_id, evidence=evidence, lines=lines, blocker=blocker)


def _run_localstack_lab(
    *,
    lab_root: Path,
    command_runner: CommandRunner | None,
    http_getter: HttpGetter | None,
    timeout_seconds: float,
) -> LiveLabRunResult:
    phase = 7
    lab_id = "cloudgoat-localstack-adaptation"
    evidence = _evidence_file(lab_root, phase=phase, lab_id=lab_id)
    container_name = "primordial-live-localstack"
    url = "http://127.0.0.1:4566/_localstack/health"
    lines = _evidence_header(phase=phase, lab_id=lab_id) + [
        "upstream_lab=https://github.com/RhinoSecurityLabs/cloudgoat",
    ]
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
    except Exception as exc:
        status = "blocked"
        blocker = str(exc)
        lines.append(f"blocker={blocker}")
    finally:
        removed = _run(("docker", "rm", "-f", container_name), command_runner=command_runner, check=False)
        lines.extend(_command_lines("docker_rm", removed))
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run local PRIMORDIAL CTF lab evidence probes.")
    parser.add_argument("--phase", type=int, choices=range(9), action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--lab-root", default=str(DEFAULT_LAB_ROOT))
    parser.add_argument("--timeout-seconds", type=float, default=90.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    phases = tuple(range(9)) if args.all or not args.phase else tuple(args.phase)
    results = tuple(
        run_phase(phase, lab_root=Path(args.lab_root), timeout_seconds=args.timeout_seconds)
        for phase in phases
    )
    payload = [result.as_payload() for result in results]
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for result in results:
            blocker = f" blocker={result.blocker}" if result.blocker else ""
            print(f"phase={result.phase} status={result.status} evidence={result.evidence_path}{blocker}")
    return 0 if all(result.status == "ready" for result in results if result.phase in READY_PHASES) else 1


if __name__ == "__main__":
    raise SystemExit(main())
