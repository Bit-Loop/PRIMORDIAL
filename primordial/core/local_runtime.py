from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_LOCAL_BOOTSTRAP_HOSTS = {"127.0.0.1", "localhost"}


def resolve_project_root(project_root: Path | None = None) -> Path:
    return Path(project_root or Path(__file__).resolve().parents[2]).resolve()


def load_project_env(project_root: Path | None = None) -> Path | None:
    """Load ignored local runtime env without overriding operator-provided values."""

    root = resolve_project_root(project_root)
    configured_path = os.getenv("PRIMORDIAL_ENV_FILE", "").strip()
    env_path = Path(configured_path).expanduser() if configured_path else root / "runtime" / "primordial.env"
    if not env_path.is_absolute():
        env_path = root / env_path
    env_path = env_path.resolve()
    if not env_path.is_file():
        return None

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        assignment = _parse_env_assignment(raw_line)
        if assignment is None:
            continue
        name, value = assignment
        os.environ.setdefault(name, value)
    return env_path


def maybe_start_bootstrap_postgres(project_root: Path | None = None) -> bool:
    if _env_bool("PRIMORDIAL_AUTO_START_BOOTSTRAP_POSTGRES", True) is False:
        return False

    root = resolve_project_root(project_root)
    database_url = os.getenv("PRIMORDIAL_DATABASE_URL", "").strip()
    port = _bootstrap_port_for_url(database_url)
    if port is None:
        return False

    pg_root = Path(os.getenv("PRIMORDIAL_BOOTSTRAP_PG_ROOT", root / "runtime" / "postgres")).resolve()
    pg_data = pg_root / "data"
    pg_socket = pg_root / "socket"
    pg_log = pg_root / "postgres.log"
    if not (pg_data / "PG_VERSION").is_file():
        return False

    pg_ctl = shutil.which("pg_ctl")
    if pg_ctl is None:
        return False

    try:
        status = subprocess.run(
            [pg_ctl, "-D", str(pg_data), "status"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if status.returncode == 0:
        return False

    try:
        pg_socket.mkdir(parents=True, exist_ok=True)
        pg_log.parent.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            [
                pg_ctl,
                "-D",
                str(pg_data),
                "-l",
                str(pg_log),
                "-o",
                f"-p {port} -k {pg_socket} -h 127.0.0.1",
                "-w",
                "start",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def _parse_env_assignment(raw_line: str) -> tuple[str, str] | None:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export "):
        line = line[len("export ") :].strip()
    name, separator, value = line.partition("=")
    if not separator:
        return None
    name = name.strip()
    if _ENV_NAME_RE.fullmatch(name) is None:
        return None
    return name, _parse_env_value(value.strip())


def _parse_env_value(value: str) -> str:
    if not value:
        return ""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    try:
        parts = shlex.split(value, posix=True)
    except ValueError:
        return value
    if len(parts) == 1:
        return parts[0]
    return " ".join(parts)


def _bootstrap_port_for_url(database_url: str) -> int | None:
    if not database_url:
        return None
    try:
        parsed = urlsplit(database_url)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme not in {"postgres", "postgresql"}:
        return None
    if host not in _LOCAL_BOOTSTRAP_HOSTS:
        return None
    bootstrap_port = _env_int("PRIMORDIAL_BOOTSTRAP_PG_PORT", 55432)
    if (port or 5432) != bootstrap_port:
        return None
    return bootstrap_port


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default
