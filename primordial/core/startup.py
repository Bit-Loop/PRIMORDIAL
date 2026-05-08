from __future__ import annotations

import importlib
import os
from dataclasses import dataclass
from typing import Any

from primordial.core.config import redact_database_url


@dataclass(slots=True)
class StartupIssue:
    summary: str
    detail: str
    fix: str


class StartupPreflightError(RuntimeError):
    def __init__(self, issues: list[StartupIssue]) -> None:
        self.issues = issues
        super().__init__(format_startup_issues(issues))


def run_startup_preflight() -> None:
    issues: list[StartupIssue] = []
    database_url = os.getenv("PRIMORDIAL_DATABASE_URL", "").strip()
    test_database_url = os.getenv("PRIMORDIAL_TEST_DATABASE_URL", "").strip()
    effective_url = database_url or test_database_url

    if not effective_url:
        issues.append(
            StartupIssue(
                summary="PRIMORDIAL_DATABASE_URL is not set",
                detail="Primordial V1 requires Postgres runtime storage and no longer starts against SQLite.",
                fix="Create a Postgres database, then export PRIMORDIAL_DATABASE_URL, for example: export PRIMORDIAL_DATABASE_URL='postgresql://primordial:<password>@localhost:5432/primordial'",
            )
        )

    psycopg_module: Any | None = None
    try:
        psycopg_module = importlib.import_module("psycopg")
    except ModuleNotFoundError:
        issues.append(
            StartupIssue(
                summary="psycopg v3 is not installed in this Python environment",
                detail="The active interpreter cannot import the Postgres driver required by RuntimeStore.",
                fix="Use a project virtualenv and install dependencies: python3 -m venv .venv && . .venv/bin/activate && python3 -m pip install -e .",
            )
        )

    if issues:
        raise StartupPreflightError(issues)

    assert psycopg_module is not None
    assert effective_url
    try:
        with psycopg_module.connect(effective_url, connect_timeout=3) as connection:
            connection.execute("CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public")
            row = connection.execute("SELECT extname FROM pg_extension WHERE extname = 'vector'").fetchone()
            if row is None:
                issues.append(
                    StartupIssue(
                        summary="pgvector extension is not enabled",
                        detail=f"Connected to {redact_database_url(effective_url)}, but the vector extension is absent.",
                        fix="Enable it once for the database: psql \"$PRIMORDIAL_DATABASE_URL\" -c 'CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;'",
                    )
                )
    except Exception as exc:  # noqa: BLE001 - startup preflight returns operator-facing diagnostics
        issues.append(_postgres_issue(effective_url, exc))

    if issues:
        raise StartupPreflightError(issues)


def format_startup_issues(issues: list[StartupIssue]) -> str:
    lines = [
        "Primordial startup preflight failed.",
        "",
        "Required V1 runtime setup:",
        "1. Use a Python environment with project dependencies installed.",
        "2. Set PRIMORDIAL_DATABASE_URL to a reachable Postgres database.",
        "3. Install and enable pgvector in that database.",
        "",
        "Detected issue(s):",
    ]
    for index, issue in enumerate(issues, start=1):
        lines.extend(
            [
                f"{index}. {issue.summary}",
                f"   Detail: {issue.detail}",
                f"   Fix: {issue.fix}",
            ]
        )
    lines.extend(
        [
            "",
            "Minimal local setup example:",
            "  python3 -m venv .venv",
            "  . .venv/bin/activate",
            "  python3 -m pip install -e .",
            "  # Install Postgres and pgvector using your OS package manager first.",
            "  createuser --pwprompt primordial        # skip if the role already exists",
            "  createdb -O primordial primordial      # skip if the database already exists",
            "  export PRIMORDIAL_DATABASE_URL='postgresql://primordial:<password>@localhost:5432/primordial'",
            "  psql \"$PRIMORDIAL_DATABASE_URL\" -c 'CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;'",
        ]
    )
    return "\n".join(lines)


def _postgres_issue(database_url: str, exc: Exception) -> StartupIssue:
    message = str(exc)
    redacted = redact_database_url(database_url)
    lowered = message.lower()
    if 'extension "vector" is not available' in lowered or "could not open extension control file" in lowered:
        return StartupIssue(
            summary="Postgres pgvector is not installed on the database server",
            detail=f"Connected to {redacted}, but Postgres cannot load extension vector: {message}",
            fix="Install the pgvector package for your Postgres version, then rerun: psql \"$PRIMORDIAL_DATABASE_URL\" -c 'CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;'",
        )
    if "permission denied to create extension" in lowered or "must be superuser" in lowered:
        return StartupIssue(
            summary="Database user cannot create pgvector extension",
            detail=f"Connected to {redacted}, but the configured user lacks extension privileges: {message}",
            fix="Have a database owner/superuser run: CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;",
        )
    return StartupIssue(
        summary="Postgres is not reachable with PRIMORDIAL_DATABASE_URL",
        detail=f"Connection/setup check failed for {redacted}: {message}",
        fix="Verify Postgres is running, the DSN is correct, credentials are valid, and the database exists.",
    )
