from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import hashlib
import json
import re

from primordial.labs.ctf.hardcode import flag_sha256


NYU_ACTIVE_RELATIVE = Path("assets/phase8-nyu-ctf-bench")
NYU_PARKED_GLOB = "phase8-nyu-ctf-bench.parked-*"
MBPTL_RELATIVE = Path("assets/phase3-mbptl/mbptl")
CTF_DOJO_RELATIVE = Path("assets/phase8-ctf-dojo")
DEFAULT_DENIED_ANCESTORS = frozenset({".git", "__pycache__", "node_modules", ".venv", "venv"})


@dataclass(frozen=True, slots=True)
class ChallengeRef:
    lab_id: str
    challenge_id: str
    repo_relpath: str
    repo_relpath_sha: str
    category: str
    compose_path: str = ""
    dockerfile_path: str = ""
    run_command: str = ""
    target_url_template: str = ""
    ground_truth_flag_sha256: str = ""
    time_budget_s: int = 300
    request_budget: int = 80

    def as_metadata(self) -> dict[str, object]:
        return {
            "ctf_lab_id": self.lab_id,
            "ctf_challenge_id": self.challenge_id,
            "ctf_category": self.category,
            "ctf_repo_relpath": self.repo_relpath,
            "ctf_repo_relpath_sha": self.repo_relpath_sha,
            "ctf_ground_truth_flag_sha256": self.ground_truth_flag_sha256,
            "ctf_time_budget_s": self.time_budget_s,
            "ctf_request_budget": self.request_budget,
        }


@dataclass(frozen=True, slots=True)
class ChallengeIndexBlocker:
    lab_id: str
    repo_relpath: str
    reason: str


@dataclass(frozen=True, slots=True)
class ChallengeIndexResult:
    challenges: tuple[ChallengeRef, ...]
    blockers: tuple[ChallengeIndexBlocker, ...] = ()


def namespaced_repo_relpath_sha(lab_id: str, repo_relpath: str) -> str:
    return hashlib.sha256(f"{lab_id}|{repo_relpath}".encode("utf-8")).hexdigest()


def load_phase_challenge_index(
    phase: int,
    *,
    lab_root: Path,
    include_parked: bool = True,
    denied_ancestors: frozenset[str] = DEFAULT_DENIED_ANCESTORS,
) -> ChallengeIndexResult:
    if phase != 8:
        if phase == 3:
            return load_mbptl_challenges(lab_root=lab_root, denied_ancestors=denied_ancestors)
        return ChallengeIndexResult(challenges=())
    results = [
        load_ctf_dojo_challenges(lab_root=lab_root, denied_ancestors=denied_ancestors),
        load_nyu_ctf_bench_challenges(lab_root=lab_root, include_parked=include_parked, denied_ancestors=denied_ancestors),
    ]
    challenges = tuple(sorted((item for result in results for item in result.challenges), key=lambda item: (item.lab_id, item.category, item.repo_relpath)))
    blockers = tuple(item for result in results for item in result.blockers)
    return ChallengeIndexResult(challenges=challenges, blockers=blockers)


def load_mbptl_challenges(
    *,
    lab_root: Path,
    denied_ancestors: frozenset[str] = DEFAULT_DENIED_ANCESTORS,
) -> ChallengeIndexResult:
    lab_id = "mbptl"
    root = Path(lab_root) / MBPTL_RELATIVE
    compose = root / "docker-compose.yml"
    if not root.is_dir() or not compose.is_file():
        return ChallengeIndexResult(challenges=())
    challenges: list[ChallengeRef] = []
    for flag_file in sorted(root.glob("*/flag*.txt")):
        repo_relpath = _safe_relative(flag_file, root)
        if _denied(repo_relpath, denied_ancestors):
            continue
        try:
            flag = flag_file.read_text(encoding="utf-8")
        except OSError:
            flag = ""
        service_dir = flag_file.parent
        dockerfile = service_dir / "Dockerfile"
        if not dockerfile.is_file():
            continue
        challenge_id = _slug(f"{service_dir.name}-{flag_file.stem}")
        challenges.append(
            ChallengeRef(
                lab_id=lab_id,
                challenge_id=challenge_id,
                repo_relpath=repo_relpath,
                repo_relpath_sha=namespaced_repo_relpath_sha(lab_id, repo_relpath),
                category="web",
                compose_path=str(compose),
                dockerfile_path=str(dockerfile),
                target_url_template="http://127.0.0.1:80/",
                ground_truth_flag_sha256=flag_sha256(flag) if flag.strip() else "",
                time_budget_s=600,
                request_budget=120,
            )
        )
    return ChallengeIndexResult(challenges=tuple(challenges))


def load_ctf_dojo_challenges(
    *,
    lab_root: Path,
    denied_ancestors: frozenset[str] = DEFAULT_DENIED_ANCESTORS,
) -> ChallengeIndexResult:
    lab_id = "ctf-dojo"
    root = Path(lab_root) / CTF_DOJO_RELATIVE
    archive = root / "ctf_archive.json"
    if not archive.is_file():
        return ChallengeIndexResult(challenges=())
    try:
        payload = json.loads(archive.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ChallengeIndexResult(challenges=(), blockers=(ChallengeIndexBlocker(lab_id=lab_id, repo_relpath="ctf_archive.json", reason=f"invalid challenge metadata: {type(exc).__name__}"),))
    if not isinstance(payload, dict):
        return ChallengeIndexResult(challenges=(), blockers=(ChallengeIndexBlocker(lab_id=lab_id, repo_relpath="ctf_archive.json", reason="challenge metadata is not an object"),))
    challenges: list[ChallengeRef] = []
    for key, value in sorted(payload.items()):
        if not isinstance(value, dict):
            continue
        repo_relpath = _ctf_dojo_repo_relpath(value)
        if not repo_relpath or _denied(repo_relpath, denied_ancestors):
            continue
        challenge_root = root / repo_relpath
        if not challenge_root.is_dir():
            continue
        compose = _first_existing(challenge_root, ("docker-compose.yml", "docker-compose.yaml"))
        dockerfile = challenge_root / "Dockerfile"
        if compose is None and not dockerfile.is_file():
            continue
        category = _slug(str(value.get("category") or "unknown"))
        challenge_id = _slug(str(value.get("challenge") or key))
        challenges.append(
            ChallengeRef(
                lab_id=lab_id,
                challenge_id=challenge_id,
                repo_relpath=repo_relpath,
                repo_relpath_sha=namespaced_repo_relpath_sha(lab_id, repo_relpath),
                category=category,
                compose_path=str(compose) if compose else "",
                dockerfile_path=str(dockerfile) if dockerfile.is_file() else "",
                time_budget_s=300,
                request_budget=80,
            )
        )
    return ChallengeIndexResult(challenges=tuple(challenges))


def load_nyu_ctf_bench_challenges(
    *,
    lab_root: Path,
    include_parked: bool = True,
    denied_ancestors: frozenset[str] = DEFAULT_DENIED_ANCESTORS,
) -> ChallengeIndexResult:
    assets = Path(lab_root) / "assets"
    roots = [assets / "phase8-nyu-ctf-bench"]
    if include_parked:
        roots.extend(sorted(assets.glob(NYU_PARKED_GLOB)))
    challenges: list[ChallengeRef] = []
    blockers: list[ChallengeIndexBlocker] = []
    for root in roots:
        if not root.is_dir():
            continue
        result = _walk_nyu_root(root, denied_ancestors=denied_ancestors)
        challenges.extend(result.challenges)
        blockers.extend(result.blockers)
    challenges.sort(key=lambda item: (item.lab_id, item.category, item.repo_relpath))
    return ChallengeIndexResult(challenges=tuple(challenges), blockers=tuple(blockers))


def _walk_nyu_root(root: Path, *, denied_ancestors: frozenset[str]) -> ChallengeIndexResult:
    lab_id = "nyu-ctf-bench"
    challenges: list[ChallengeRef] = []
    blockers: list[ChallengeIndexBlocker] = []
    for manifest in sorted(root.rglob("challenge.json")):
        relative = _safe_relative(manifest.parent, root)
        if _denied(relative, denied_ancestors):
            continue
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            blockers.append(ChallengeIndexBlocker(lab_id=lab_id, repo_relpath=relative, reason=f"invalid challenge metadata: {type(exc).__name__}"))
            continue
        if not isinstance(payload, dict):
            blockers.append(ChallengeIndexBlocker(lab_id=lab_id, repo_relpath=relative, reason="challenge metadata is not an object"))
            continue
        compose = _first_existing(manifest.parent, ("docker-compose.yml", "docker-compose.yaml"))
        dockerfile = manifest.parent / "Dockerfile"
        if compose is None and not dockerfile.is_file():
            continue
        flag = payload.get("flag")
        category = _category(payload, relative)
        port = _positive_int(payload.get("port") or payload.get("internal_port"))
        challenges.append(
            ChallengeRef(
                lab_id=lab_id,
                challenge_id=_challenge_id(payload, relative),
                repo_relpath=relative,
                repo_relpath_sha=namespaced_repo_relpath_sha(lab_id, relative),
                category=category,
                compose_path=str(compose) if compose else "",
                dockerfile_path=str(dockerfile) if dockerfile.is_file() else "",
                target_url_template=f"http://127.0.0.1:{port}/" if port else "",
                ground_truth_flag_sha256=flag_sha256(str(flag)) if isinstance(flag, str) and flag.strip() else "",
                time_budget_s=300,
                request_budget=80,
            )
        )
    return ChallengeIndexResult(challenges=tuple(challenges), blockers=tuple(blockers))


def _first_existing(root: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def _safe_relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _denied(repo_relpath: str, denied_ancestors: frozenset[str]) -> bool:
    return any(part in denied_ancestors for part in Path(repo_relpath).parts)


def _category(payload: dict[str, Any], repo_relpath: str) -> str:
    value = payload.get("category")
    if isinstance(value, str) and value.strip():
        return _slug(value)
    parts = Path(repo_relpath).parts
    return _slug(parts[-2] if len(parts) >= 2 else "unknown")


def _challenge_id(payload: dict[str, Any], repo_relpath: str) -> str:
    value = payload.get("name")
    if isinstance(value, str) and value.strip():
        return _slug(value)
    return _slug(repo_relpath)


def _ctf_dojo_repo_relpath(payload: dict[str, Any]) -> str:
    value = payload.get("path")
    if not isinstance(value, str) or not value.strip():
        return ""
    path = Path(value.strip())
    if path.is_absolute() or ".." in path.parts:
        return ""
    return path.as_posix()


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", str(value).strip().lower()).strip("-") or "challenge"


def _positive_int(value: object) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return number if number > 0 else 0
