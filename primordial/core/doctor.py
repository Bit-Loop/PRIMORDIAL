from __future__ import annotations

from dataclasses import dataclass
import importlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any

from primordial.core.config import AppConfig, redact_database_url
from primordial.core.local_runtime import load_project_env
from primordial.core.storage.runtime import _SCHEMA_VERSION


@dataclass(slots=True)
class DoctorCheck:
    id: str
    label: str
    status: str
    details: dict[str, Any]

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "status": self.status,
            "details": self.details,
        }


def run_doctor(*, project_root: Path | None = None) -> dict[str, Any]:
    root = Path(project_root or Path(__file__).resolve().parents[2]).resolve()
    load_project_env(root)
    checks: list[DoctorCheck] = []
    config = _load_config(root, checks)
    database_url = _effective_database_url()
    database_schema = config.database_schema if config else None
    _check_database(checks, database_url, database_schema)
    _check_runtime_writable(checks, root, config)
    _check_tracked_runtime_files(checks, root)
    ok = all(check.status == "pass" for check in checks)
    return {
        "ok": ok,
        "status": "ok" if ok else "fail",
        "checks": [check.as_payload() for check in checks],
    }


def format_doctor_report(payload: dict[str, Any]) -> str:
    lines = [f"Primordial doctor: {str(payload.get('status', 'fail')).upper()}"]
    for check in payload.get("checks", []):
        if not isinstance(check, dict):
            continue
        status = str(check.get("status", "fail")).upper()
        label = str(check.get("label", check.get("id", "check")))
        details = check.get("details", {})
        suffix = ""
        if isinstance(details, dict):
            if details.get("summary"):
                suffix = f" - {details['summary']}"
            elif details.get("error"):
                suffix = f" - {details['error']}"
            elif details.get("value") is not None:
                suffix = f" - {details['value']}"
        lines.append(f"[{status}] {label}{suffix}")
    return "\n".join(lines)


def _load_config(root: Path, checks: list[DoctorCheck]) -> AppConfig | None:
    try:
        return AppConfig.from_env(project_root=root)
    except Exception as exc:  # noqa: BLE001 - surfaced as a doctor check
        checks.append(
            DoctorCheck(
                id="config",
                label="Runtime configuration",
                status="fail",
                details={"error": str(exc)},
            )
        )
        return None


def _effective_database_url() -> str:
    return os.getenv("PRIMORDIAL_DATABASE_URL", "").strip() or os.getenv("PRIMORDIAL_TEST_DATABASE_URL", "").strip()


def _database_not_checked_check(check_id: str, label: str) -> DoctorCheck:
    return DoctorCheck(check_id, label, "fail", {"error": "database was not checked"})


def _append_database_unchecked_checks(checks: list[DoctorCheck], db_reachable: DoctorCheck) -> None:
    checks.extend(
        [
            db_reachable,
            _database_not_checked_check("pgvector_installed", "pgvector installed"),
            _database_not_checked_check("schema_version", "Schema version"),
        ]
    )


def _check_schema_version(checks: list[DoctorCheck], connection: Any) -> None:
    relation = connection.execute("SELECT to_regclass('schema_version') AS relation").fetchone()
    if not relation or not relation["relation"]:
        checks.append(DoctorCheck("schema_version", "Schema version", "fail", {"error": "schema_version table is missing"}))
        return

    row = connection.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").fetchone()
    if row is None:
        checks.append(DoctorCheck("schema_version", "Schema version", "fail", {"error": "schema_version is empty"}))
        return

    version = int(row["version"])
    checks.append(
        DoctorCheck(
            "schema_version",
            "Schema version",
            "pass" if version == _SCHEMA_VERSION else "fail",
            {"value": version, "expected": _SCHEMA_VERSION},
        )
    )


def _check_database(checks: list[DoctorCheck], database_url: str, database_schema: str | None) -> None:
    if not database_url:
        _append_database_unchecked_checks(
            checks,
            DoctorCheck(
                id="db_reachable",
                label="DB reachable",
                status="fail",
                details={"error": "PRIMORDIAL_DATABASE_URL is not set"},
            ),
        )
        return
    try:
        psycopg = importlib.import_module("psycopg")
        dict_row = importlib.import_module("psycopg.rows").dict_row
    except ModuleNotFoundError as exc:
        _append_database_unchecked_checks(
            checks,
            DoctorCheck("db_reachable", "DB reachable", "fail", {"error": f"psycopg v3 is not installed: {exc}"}),
        )
        return

    redacted = redact_database_url(database_url)
    try:
        with psycopg.connect(database_url, connect_timeout=3, row_factory=dict_row) as connection:
            if database_schema:
                connection.execute(f"SET search_path TO {_quote_ident(database_schema)}, public")
            checks.append(
                DoctorCheck("db_reachable", "DB reachable", "pass", {"url": redacted, "schema": database_schema or "default"})
            )
            vector = connection.execute("SELECT extname FROM pg_extension WHERE extname = 'vector'").fetchone()
            checks.append(
                DoctorCheck(
                    "pgvector_installed",
                    "pgvector installed",
                    "pass" if vector else "fail",
                    {"value": "vector" if vector else "missing"},
                )
            )
            _check_schema_version(checks, connection)
    except Exception as exc:  # noqa: BLE001 - surfaced as a doctor check
        _append_database_unchecked_checks(
            checks,
            DoctorCheck("db_reachable", "DB reachable", "fail", {"url": redacted, "error": str(exc)}),
        )


def _check_runtime_writable(checks: list[DoctorCheck], root: Path, config: AppConfig | None) -> None:
    if config is None:
        runtime_dir = Path(os.getenv("PRIMORDIAL_RUNTIME_DIR", root / "runtime")).resolve()
        paths = [runtime_dir]
    else:
        paths = [
            config.runtime_dir,
            config.artifacts_dir,
            config.checkpoints_dir,
            config.exports_dir,
            config.secrets_dir,
        ]
    failures: list[dict[str, str]] = []
    for path in paths:
        writable, detail = _path_writable(path)
        if not writable:
            failures.append({"path": str(path), "error": detail})
    checks.append(
        DoctorCheck(
            "runtime_dirs_writable",
            "Runtime dirs writable",
            "fail" if failures else "pass",
            {"paths": [str(path) for path in paths], "failures": failures},
        )
    )


def _path_writable(path: Path) -> tuple[bool, str]:
    probe_dir = path if path.exists() and path.is_dir() else _nearest_existing_parent(path)
    if probe_dir is None:
        return False, "no existing parent directory"
    try:
        with tempfile.NamedTemporaryFile(prefix=".primordial-doctor-", dir=probe_dir, delete=True):
            pass
        return True, "writable"
    except Exception as exc:  # noqa: BLE001 - surfaced as a doctor check
        return False, str(exc)


def _nearest_existing_parent(path: Path) -> Path | None:
    current = path
    while not current.exists():
        parent = current.parent
        if parent == current:
            return None
        current = parent
    return current if current.is_dir() else current.parent


def _quote_ident(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _check_tracked_runtime_files(checks: list[DoctorCheck], root: Path) -> None:
    try:
        completed = subprocess.run(
            ["git", "ls-files", "runtime"],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced as a doctor check
        checks.append(
            DoctorCheck("runtime_files_untracked", "No tracked runtime files", "fail", {"error": str(exc)})
        )
        return
    files = [line for line in completed.stdout.splitlines() if line.strip()]
    checks.append(
        DoctorCheck(
            "runtime_files_untracked",
            "No tracked runtime files",
            "pass" if completed.returncode == 0 and not files else "fail",
            {"files": files, "error": completed.stderr.strip()},
        )
    )


def dumps_doctor_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)
