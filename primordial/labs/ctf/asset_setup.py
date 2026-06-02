from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

DEFAULT_LAB_ROOT = Path("/run/media/bitloop/DREAD/primordial-labs")

CommandRunner = Callable[[tuple[str, ...]], subprocess.CompletedProcess[str]]


@dataclass(frozen=True, slots=True)
class LabAsset:
    phase: int
    lab_id: str
    repo_url: str
    dest_name: str
    required_tools: tuple[str, ...] = ()
    denied_paths: tuple[str, ...] = ()
    sparse_paths: tuple[str, ...] = ()
    provisioning_note: str = ""


@dataclass(frozen=True, slots=True)
class LabAssetSetupResult:
    phase: int
    lab_id: str
    status: str
    asset_path: str
    evidence_path: str
    evidence_ref: str
    missing_tools: tuple[str, ...] = ()
    blocker: str = ""

    def as_payload(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "lab_id": self.lab_id,
            "status": self.status,
            "asset_path": self.asset_path,
            "evidence_path": self.evidence_path,
            "evidence_ref": self.evidence_ref,
            "missing_tools": list(self.missing_tools),
            "blocker": self.blocker,
        }


LAB_ASSETS: tuple[LabAsset, ...] = (
    LabAsset(
        phase=3,
        lab_id="mbptl",
        repo_url="https://github.com/bayufedra/MBPTL.git",
        dest_name="phase3-mbptl",
        required_tools=("docker", "docker-compose"),
        denied_paths=("writeup/",),
        sparse_paths=("mbptl", "setup.sh", "INSTALL.md", "README.md", "TASK.md", "SECURITY.md", "LICENSE", "CHANGELOG.md"),
        provisioning_note="MBPTL is cloned without the writeup directory; run only local container assets.",
    ),
    LabAsset(
        phase=4,
        lab_id="cicd-goat",
        repo_url="https://github.com/cider-security-research/cicd-goat.git",
        dest_name="phase4-cicd-goat",
        required_tools=("docker", "docker-compose"),
        denied_paths=("solutions/", "writeups/", "docs/solutions/"),
        provisioning_note="CI/CD Goat stays local; solution/writeup paths are excluded from PRIMORDIAL context.",
    ),
    LabAsset(
        phase=5,
        lab_id="kubernetes-goat",
        repo_url="https://github.com/madhuakula/kubernetes-goat.git",
        dest_name="phase5-kubernetes-goat",
        required_tools=("docker", "kubectl", "kind", "helm"),
        denied_paths=("solutions/", "writeups/"),
        provisioning_note="Kubernetes Goat requires a local cluster toolchain before provisioning.",
    ),
    LabAsset(
        phase=6,
        lab_id="goad",
        repo_url="https://github.com/Orange-Cyberdefense/GOAD.git",
        dest_name="phase6-goad",
        required_tools=("git", "docker", "virsh", "qemu-system-x86_64", "ansible-playbook", "vagrant"),
        denied_paths=("docs/walkthroughs/", "writeups/", "solutions/"),
        provisioning_note="Use GOAD-Light first; VM provisioning requires local virtualization and Ansible/Vagrant tooling.",
    ),
    LabAsset(
        phase=8,
        lab_id="dreadgoad",
        repo_url="https://github.com/dreadnode/DreadGOAD.git",
        dest_name="phase8-dreadgoad",
        required_tools=("git", "terraform"),
        denied_paths=("writeups/", "solutions/"),
        provisioning_note="DreadGOAD is a benchmark reference; public cloud provisioning remains disallowed.",
    ),
    LabAsset(
        phase=8,
        lab_id="ctf-dojo",
        repo_url="https://github.com/amazon-science/CTF-Dojo.git",
        dest_name="phase8-ctf-dojo",
        required_tools=("git", "docker", "python3"),
        denied_paths=("writeups/", "solutions/", "trajectories/", "find_writeups.py"),
        provisioning_note="CTF-Dojo assets are cloned as executable benchmark scaffolding, not solution context.",
    ),
    LabAsset(
        phase=8,
        lab_id="nyu-ctf-bench",
        repo_url="https://github.com/NYU-LLM-CTF/NYU_CTF_Bench.git",
        dest_name="phase8-nyu-ctf-bench",
        required_tools=("git", "docker", "python3"),
        denied_paths=("writeups/", "solutions/", "leaderboard_submissions/"),
        provisioning_note="NYU CTF Bench is cloned for local benchmark tasks and evidence-backed scoring.",
    ),
)


def setup_phase_assets(
    phase: int,
    *,
    lab_root: Path = DEFAULT_LAB_ROOT,
    command_runner: CommandRunner | None = None,
    update: bool = False,
) -> tuple[LabAssetSetupResult, ...]:
    selected = tuple(asset for asset in LAB_ASSETS if asset.phase == phase)
    if not selected:
        return (_blocked_phase_result(phase, lab_root=lab_root),)
    return tuple(setup_asset(asset, lab_root=lab_root, command_runner=command_runner, update=update) for asset in selected)


def setup_asset(
    asset: LabAsset,
    *,
    lab_root: Path = DEFAULT_LAB_ROOT,
    command_runner: CommandRunner | None = None,
    update: bool = False,
) -> LabAssetSetupResult:
    asset_dir = lab_root / "assets" / asset.dest_name
    evidence = _evidence_file(lab_root, phase=asset.phase, lab_id=asset.lab_id)
    lines = _evidence_header(asset) + [f"asset_path={asset_dir}", f"update={str(update).lower()}"]
    missing_tools = _missing_tools(asset.required_tools)
    lines.append(f"missing_tools={','.join(missing_tools)}")
    lines.extend(f"denied_path={path}" for path in asset.denied_paths)
    if asset.provisioning_note:
        lines.append(f"provisioning_note={asset.provisioning_note}")
    try:
        command_results = _clone_or_update_asset(asset, asset_dir, command_runner=command_runner, update=update)
        for label, result in command_results:
            lines.extend(_command_lines(label, result))
        removed_denied_paths = _remove_denied_paths(asset, asset_dir)
        lines.extend(f"denied_path_removed={path}" for path in removed_denied_paths)
        head = _git_head(asset_dir, command_runner=command_runner)
        if head:
            lines.append(f"repo_head={head}")
        status = "asset_ready" if not missing_tools else "tooling_blocked"
        blocker = "" if not missing_tools else f"missing local tool(s): {', '.join(missing_tools)}"
        lines.append(f"status={status}")
        if blocker:
            lines.append(f"blocker={blocker}")
    except Exception as exc:  # noqa: BLE001 - asset setup records any clone or filesystem failure as a blocker
        status = "blocked"
        blocker = str(exc)
        lines.append(f"status={status}")
        lines.append(f"blocker={blocker}")
    return _write_result(
        phase=asset.phase,
        lab_id=asset.lab_id,
        status=status,
        asset_path=asset_dir,
        evidence=evidence,
        lines=lines,
        missing_tools=missing_tools,
        blocker=blocker,
    )


def setup_all_assets(
    *,
    lab_root: Path = DEFAULT_LAB_ROOT,
    command_runner: CommandRunner | None = None,
    update: bool = False,
) -> tuple[LabAssetSetupResult, ...]:
    results: list[LabAssetSetupResult] = []
    for asset in LAB_ASSETS:
        results.append(setup_asset(asset, lab_root=lab_root, command_runner=command_runner, update=update))
    return tuple(results)


def _clone_or_update_asset(
    asset: LabAsset,
    asset_dir: Path,
    *,
    command_runner: CommandRunner | None,
    update: bool,
) -> tuple[tuple[str, subprocess.CompletedProcess[str]], ...]:
    results: list[tuple[str, subprocess.CompletedProcess[str]]] = []
    asset_dir.parent.mkdir(parents=True, exist_ok=True)
    if (asset_dir / ".git").is_dir():
        if update:
            results.append(("git_fetch", _run(("git", "-C", str(asset_dir), "fetch", "--depth", "1", "origin"), command_runner=command_runner)))
            results.append(("git_reset", _run(("git", "-C", str(asset_dir), "reset", "--hard", "FETCH_HEAD"), command_runner=command_runner)))
        else:
            results.append(("git_existing", _run(("git", "-C", str(asset_dir), "rev-parse", "--is-inside-work-tree"), command_runner=command_runner)))
        return tuple(results)
    clone = (
        "git",
        "clone",
        "--filter=blob:none",
        "--depth",
        "1",
        *(_sparse_clone_args(asset)),
        asset.repo_url,
        str(asset_dir),
    )
    results.append(("git_clone", _run(clone, command_runner=command_runner)))
    if asset.sparse_paths:
        results.append(("git_sparse_init", _run(("git", "-C", str(asset_dir), "sparse-checkout", "init", "--cone"), command_runner=command_runner)))
        results.append(
            (
                "git_sparse_set",
                _run(("git", "-C", str(asset_dir), "sparse-checkout", "set", *asset.sparse_paths), command_runner=command_runner),
            )
        )
        results.append(("git_checkout", _run(("git", "-C", str(asset_dir), "checkout"), command_runner=command_runner)))
    return tuple(results)


def _sparse_clone_args(asset: LabAsset) -> tuple[str, ...]:
    return ("--no-checkout",) if asset.sparse_paths else ()


def _run(command: tuple[str, ...], *, command_runner: CommandRunner | None) -> subprocess.CompletedProcess[str]:
    if command_runner is None:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
    else:
        result = command_runner(command)
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(command[:3])}")
    return result


def _git_head(asset_dir: Path, *, command_runner: CommandRunner | None) -> str:
    if not (asset_dir / ".git").is_dir():
        return ""
    try:
        result = _run(("git", "-C", str(asset_dir), "rev-parse", "HEAD"), command_runner=command_runner)
    except RuntimeError:
        return ""
    return result.stdout.strip()


def _remove_denied_paths(asset: LabAsset, asset_dir: Path) -> tuple[str, ...]:
    if not asset_dir.exists():
        return ()
    root = asset_dir.resolve()
    removed: list[str] = []
    for rel_path in asset.denied_paths:
        target = (asset_dir / rel_path).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            raise RuntimeError(f"denied path escapes asset root: {rel_path}") from None
        if not target.exists():
            continue
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
        removed.append(rel_path)
    return tuple(removed)


def _missing_tools(tools: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(tool for tool in tools if shutil.which(tool) is None)


def _blocked_phase_result(phase: int, *, lab_root: Path) -> LabAssetSetupResult:
    evidence = _evidence_file(lab_root, phase=phase, lab_id=f"phase-{phase}-asset-setup")
    blocker = "phase has no configured local asset source"
    lines = [
        f"created_at={datetime.now(UTC).isoformat()}",
        f"phase={phase}",
        "status=blocked",
        f"blocker={blocker}",
    ]
    return _write_result(
        phase=phase,
        lab_id=f"phase-{phase}-asset-setup",
        status="blocked",
        asset_path=lab_root / "assets",
        evidence=evidence,
        lines=lines,
        missing_tools=(),
        blocker=blocker,
    )


def _evidence_file(lab_root: Path, *, phase: int, lab_id: str) -> Path:
    evidence_dir = lab_root / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    return evidence_dir / f"phase{phase}-{lab_id}-asset-setup.txt"


def _evidence_header(asset: LabAsset) -> list[str]:
    return [
        f"created_at={datetime.now(UTC).isoformat()}",
        f"phase={asset.phase}",
        f"lab_id={asset.lab_id}",
        f"repo_url={asset.repo_url}",
        "completion_indicator=autonomous_flags",
        "asset_setup_only=true",
    ]


def _command_lines(label: str, result: subprocess.CompletedProcess[str]) -> list[str]:
    return [
        f"{label}.returncode={result.returncode}",
        f"{label}.stdout_sha256={_sha256_text(result.stdout or '')}",
        f"{label}.stderr_sha256={_sha256_text(result.stderr or '')}",
        f"{label}.stdout_bytes={len((result.stdout or '').encode('utf-8'))}",
        f"{label}.stderr_bytes={len((result.stderr or '').encode('utf-8'))}",
    ]


def _write_result(
    *,
    phase: int,
    lab_id: str,
    status: str,
    asset_path: Path,
    evidence: Path,
    lines: list[str],
    missing_tools: tuple[str, ...],
    blocker: str,
) -> LabAssetSetupResult:
    evidence.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    evidence_ref = f"evidence:asset-setup:{_sha256_bytes(evidence.read_bytes())[:16]}"
    return LabAssetSetupResult(
        phase=phase,
        lab_id=lab_id,
        status=status,
        asset_path=str(asset_path),
        evidence_path=str(evidence),
        evidence_ref=evidence_ref,
        missing_tools=missing_tools,
        blocker=blocker,
    )


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Clone or update local PRIMORDIAL CTF lab assets.")
    parser.add_argument("--phase", type=int, choices=range(9), action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--lab-root", default=str(DEFAULT_LAB_ROOT))
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    lab_root = Path(args.lab_root)
    phases = tuple(range(3, 9)) if args.all or not args.phase else tuple(args.phase)
    results: list[LabAssetSetupResult] = []
    for phase in phases:
        results.extend(setup_phase_assets(phase, lab_root=lab_root, update=args.update))
    payload = [result.as_payload() for result in results]
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for result in results:
            blocker = f" blocker={result.blocker}" if result.blocker else ""
            print(f"phase={result.phase} lab={result.lab_id} status={result.status} evidence={result.evidence_path}{blocker}")
    return 0 if all(result.status in {"asset_ready", "tooling_blocked"} for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
