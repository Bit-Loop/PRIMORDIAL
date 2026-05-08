from __future__ import annotations

import atexit
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
from urllib.parse import quote


_CLUSTER: "_TempPostgresCluster | None" = None


def ensure_test_database_url() -> str:
    existing = os.getenv("PRIMORDIAL_TEST_DATABASE_URL") or os.getenv("PRIMORDIAL_DATABASE_URL")
    if existing:
        os.environ.setdefault("PRIMORDIAL_TEST_DATABASE_URL", existing)
        return existing

    global _CLUSTER
    if _CLUSTER is None:
        _CLUSTER = _TempPostgresCluster()
        _CLUSTER.start()
        atexit.register(_CLUSTER.stop)
    os.environ["PRIMORDIAL_TEST_DATABASE_URL"] = _CLUSTER.database_url
    return _CLUSTER.database_url


class _TempPostgresCluster:
    def __init__(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory(prefix="primordial-pg-")
        root = Path(self._temp_dir.name)
        self.data_dir = root / "data"
        self.socket_dir = root / "socket"
        self.socket_dir.mkdir(parents=True, exist_ok=True)
        self.port = _free_port()
        self.user = "primordial"
        self.database = "primordial_test"
        self.database_url = (
            f"postgresql://{self.user}@/{self.database}"
            f"?host={quote(str(self.socket_dir), safe='')}&port={self.port}"
        )

    def start(self) -> None:
        initdb = _require_bin("initdb")
        pg_ctl = _require_bin("pg_ctl")
        createdb = _require_bin("createdb")
        psql = _require_bin("psql")
        subprocess.run(
            [initdb, "-D", str(self.data_dir), "-A", "trust", "-U", self.user],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        subprocess.run(
            [
                pg_ctl,
                "-D",
                str(self.data_dir),
                "-o",
                f"-p {self.port} -k {self.socket_dir}",
                "-w",
                "start",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        subprocess.run(
            [createdb, "-h", str(self.socket_dir), "-p", str(self.port), "-U", self.user, self.database],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            subprocess.run(
                [
                    psql,
                    "-h",
                    str(self.socket_dir),
                    "-p",
                    str(self.port),
                    "-U",
                    self.user,
                    "-d",
                    self.database,
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-c",
                    "CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            self.stop()
            raise RuntimeError(
                "Postgres test bootstrap requires the pgvector extension to be installed. "
                f"psql stderr: {exc.stderr.strip()}"
            ) from exc

    def stop(self) -> None:
        pg_ctl = shutil.which("pg_ctl")
        if pg_ctl and self.data_dir.exists():
            subprocess.run(
                [pg_ctl, "-D", str(self.data_dir), "-m", "fast", "-w", "stop"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        self._temp_dir.cleanup()


def _require_bin(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"Postgres test bootstrap requires `{name}` on PATH.")
    return path


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
