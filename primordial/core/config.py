from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import os
from urllib.parse import urlsplit, urlunsplit

from primordial.core.domain.enums import AutonomyMode
from primordial.core.domain.constants import PROFILE_DEFAULT_TASK_ALLOWLIST
from primordial.core.local_runtime import load_project_env


@dataclass(slots=True)
class ModelTopology:
    local_fast: str = "gemma4:e4b"
    local_deep: str = "deepseek-r1:8b"
    local_code: str = "qwen3-coder-next:q4_K_M"
    local_compact: str = "phi4-reasoning"
    local_compact_rich: str = "phi4-reasoning"
    cold_review_primary: str = "gemma3:27b"
    cold_review_secondary: str = "qwen2.5:32b"
    remote_premium: str = "claude-sonnet-4"


@dataclass(slots=True)
class AutonomySettings:
    mode: AutonomyMode = AutonomyMode.ASSISTED
    allow_remote_premium: bool = False
    allow_exploitative_actions: bool = False
    allow_agent_safety_approval: bool = True
    require_human_for_high_risk: bool = True
    max_poc_timeout_seconds: int = 30
    max_poc_requests: int = 20
    # Maximum verified interests a CHAIN_CANDIDATES task may review in one bounded pass.
    max_chaining_fanout: int = 5
    # Upper bound on task.max_attempts regardless of blueprint value. Wired in workflow._plan_task.
    max_auto_retries: int = 2
    memory_light_interval_minutes: int = 10
    memory_heavy_interval_minutes: int = 180
    # Daily spend cap for REMOTE_PREMIUM route. Enforced by PolicyEngine using the remote cost ledger.
    daily_remote_budget: float = 25.0
    hot_path_concurrency: int = 1
    compact_path_concurrency: int = 2
    cold_path_concurrency: int = 1
    remote_premium_concurrency: int = 1
    high_risk_concurrency: int = 1
    defer_retry_seconds: int = 20
    # After this many consecutive defers a task escalates to NEEDS_APPROVAL rather than
    # continuing to defer silently. Prevents infinite scheduler-busy loops.
    max_defer_count: int = 6
    # Hard cap on total tasks that may be RUNNING at once across all lanes.
    # Enforced by ModelScheduler.offer() before any per-lane concurrency check.
    max_total_concurrent_tasks: int = 4
    # Agents whose agent_safety_approval is accepted by the policy engine.
    approved_reviewer_agents: frozenset[str] = field(
        default_factory=lambda: frozenset({"behavior_verifier", "policy_verifier", "exploit_safety_reviewer"})
    )
    # Profile → task kinds that may be planned without explicit allow_* metadata.
    profile_task_allowlist: dict[str, frozenset[str]] = field(
        default_factory=lambda: dict(PROFILE_DEFAULT_TASK_ALLOWLIST)
    )


@dataclass(slots=True)
class AppConfig:
    project_root: Path
    runtime_dir: Path
    database_url: str
    database_schema: str | None
    artifacts_dir: Path
    chat_logs_dir: Path
    checkpoints_dir: Path
    crash_journal_path: Path
    findings_dir: Path
    notion_exports_dir: Path
    exports_dir: Path
    manifests_dir: Path
    catalog_dir: Path
    skills_dir: Path
    secrets_dir: Path
    credentials_path: Path
    topology: ModelTopology = field(default_factory=ModelTopology)
    autonomy: AutonomySettings = field(default_factory=AutonomySettings)
    agent_chat_base_url: str = "http://127.0.0.1:8787"
    agent_chat_api_key: str | None = None
    agent_chat_provider: str = "claude"
    agent_chat_model: str | None = None
    agent_chat_timeout_seconds: int = 300
    agent_chat_cwd: Path | None = None
    agent_chat_safe_guard: bool = True
    agent_chat_codex_sandbox: str = "read-only"
    agent_chat_claude_permission_mode: str = "dontAsk"
    agent_chat_auto_start: bool = True
    use_only_wrapper_mode: bool = False
    # Maximum items written into any single evidence metadata list or note body
    # list. Increase if large targets are silently dropping evidence.
    max_evidence_items: int = 50
    # Wordlist used by web content discovery. Configurable so operators can
    # substitute a custom list without code changes.
    content_discovery_wordlist: str = "/usr/share/wfuzz/wordlists/general/common.txt"

    @classmethod
    def from_env(cls, project_root: Path | None = None) -> "AppConfig":
        root = Path(project_root or Path(__file__).resolve().parents[2]).resolve()
        load_project_env(root)
        runtime_dir = Path(os.getenv("PRIMORDIAL_RUNTIME_DIR", root / "runtime")).resolve()
        database_url = os.getenv("PRIMORDIAL_DATABASE_URL", "").strip()
        database_schema = None
        if not database_url:
            database_url = os.getenv("PRIMORDIAL_TEST_DATABASE_URL", "").strip()
            if database_url:
                digest = hashlib.sha1(str(root).encode("utf-8")).hexdigest()[:12]
                database_schema = f"primordial_test_{digest}"
        if not database_url:
            raise RuntimeError(
                "PRIMORDIAL_DATABASE_URL is required. "
                "Primordial no longer supports SQLite runtime storage."
            )
        artifacts_dir = Path(
            os.getenv("PRIMORDIAL_ARTIFACTS_DIR", runtime_dir / "artifacts")
        ).resolve()
        chat_logs_dir = Path(
            os.getenv("PRIMORDIAL_CHAT_LOGS_DIR", root / "chat_log")
        ).resolve()
        checkpoints_dir = Path(
            os.getenv("PRIMORDIAL_CHECKPOINTS_DIR", runtime_dir / "checkpoints")
        ).resolve()
        crash_journal_path = Path(
            os.getenv("PRIMORDIAL_CRASH_JOURNAL_PATH", runtime_dir / "crash.journal")
        ).resolve()
        findings_dir = Path(
            os.getenv("PRIMORDIAL_FINDINGS_DIR", root / "findings")
        ).resolve()
        notion_exports_dir = Path(
            os.getenv("PRIMORDIAL_NOTION_EXPORTS_DIR", findings_dir / "notion")
        ).resolve()
        exports_dir = Path(
            os.getenv("PRIMORDIAL_EXPORTS_DIR", runtime_dir / "exports")
        ).resolve()
        manifests_dir = Path(
            os.getenv("PRIMORDIAL_MANIFESTS_DIR", root / "manifests")
        ).resolve()
        catalog_dir = Path(
            os.getenv("PRIMORDIAL_CATALOG_DIR", root / "catalog")
        ).resolve()
        skills_dir = Path(
            os.getenv("PRIMORDIAL_SKILLS_DIR", root / "skills")
        ).resolve()
        secrets_dir = Path(
            os.getenv("PRIMORDIAL_SECRETS_DIR", runtime_dir / "secrets")
        ).resolve()
        credentials_path = Path(
            os.getenv("PRIMORDIAL_CREDENTIALS_PATH", secrets_dir / "credentials.json")
        ).resolve()
        autonomy_mode = AutonomyMode(
            os.getenv("PRIMORDIAL_AUTONOMY_MODE", AutonomyMode.ASSISTED.value)
        )
        autonomy = AutonomySettings(
            mode=autonomy_mode,
            allow_remote_premium=_env_bool("PRIMORDIAL_ALLOW_REMOTE_PREMIUM", False),
            allow_exploitative_actions=_env_bool("PRIMORDIAL_ALLOW_EXPLOITATIVE_ACTIONS", False),
            allow_agent_safety_approval=_env_bool("PRIMORDIAL_ALLOW_AGENT_SAFETY_APPROVAL", True),
            max_poc_timeout_seconds=_env_int("PRIMORDIAL_MAX_POC_TIMEOUT_SECONDS", 30),
            max_poc_requests=_env_int("PRIMORDIAL_MAX_POC_REQUESTS", 20),
            max_chaining_fanout=_env_int("PRIMORDIAL_MAX_CHAINING_FANOUT", 5),
            max_auto_retries=_env_int("PRIMORDIAL_MAX_AUTO_RETRIES", 2),
            daily_remote_budget=_env_float("PRIMORDIAL_DAILY_REMOTE_BUDGET", 25.0),
        )
        content_discovery_wordlist = os.getenv(
            "PRIMORDIAL_CONTENT_DISCOVERY_WORDLIST",
            "/usr/share/wfuzz/wordlists/general/common.txt",
        )
        max_evidence_items = int(os.getenv("PRIMORDIAL_MAX_EVIDENCE_ITEMS", "50"))
        agent_chat_cwd_raw = os.getenv("PRIMORDIAL_AGENT_CHAT_CWD", "").strip()
        agent_chat_cwd = Path(agent_chat_cwd_raw).expanduser().resolve() if agent_chat_cwd_raw else None
        return cls(
            project_root=root,
            runtime_dir=runtime_dir,
            database_url=database_url,
            database_schema=database_schema,
            artifacts_dir=artifacts_dir,
            chat_logs_dir=chat_logs_dir,
            checkpoints_dir=checkpoints_dir,
            crash_journal_path=crash_journal_path,
            findings_dir=findings_dir,
            notion_exports_dir=notion_exports_dir,
            exports_dir=exports_dir,
            manifests_dir=manifests_dir,
            catalog_dir=catalog_dir,
            skills_dir=skills_dir,
            secrets_dir=secrets_dir,
            credentials_path=credentials_path,
            autonomy=autonomy,
            agent_chat_base_url=os.getenv("PRIMORDIAL_AGENT_CHAT_BASE_URL", "http://127.0.0.1:8787").strip()
            or "http://127.0.0.1:8787",
            agent_chat_api_key=os.getenv("PRIMORDIAL_AGENT_CHAT_API_KEY") or os.getenv("CHAT_API_KEY") or None,
            agent_chat_provider=os.getenv("PRIMORDIAL_AGENT_CHAT_PROVIDER", "claude").strip().lower() or "claude",
            agent_chat_model=os.getenv("PRIMORDIAL_AGENT_CHAT_MODEL") or None,
            agent_chat_timeout_seconds=_env_int("PRIMORDIAL_AGENT_CHAT_TIMEOUT_SECONDS", 300),
            agent_chat_cwd=agent_chat_cwd,
            agent_chat_safe_guard=_env_bool("PRIMORDIAL_AGENT_CHAT_SAFE_GUARD", True),
            agent_chat_codex_sandbox=os.getenv("PRIMORDIAL_AGENT_CHAT_CODEX_SANDBOX", "read-only").strip()
            or "read-only",
            agent_chat_claude_permission_mode=os.getenv(
                "PRIMORDIAL_AGENT_CHAT_CLAUDE_PERMISSION_MODE",
                "dontAsk",
            ).strip()
            or "dontAsk",
            agent_chat_auto_start=_env_bool("PRIMORDIAL_AGENT_CHAT_AUTO_START", True),
            use_only_wrapper_mode=_env_bool("PRIMORDIAL_USE_ONLY_WRAPPER_MODE", False),
            content_discovery_wordlist=content_discovery_wordlist,
            max_evidence_items=max_evidence_items,
        )

    def ensure_directories(self) -> None:
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.chat_logs_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.notion_exports_dir.mkdir(parents=True, exist_ok=True)
        self.exports_dir.mkdir(parents=True, exist_ok=True)
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        self.catalog_dir.mkdir(parents=True, exist_ok=True)
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        self.secrets_dir.mkdir(parents=True, exist_ok=True)
        self.secrets_dir.chmod(0o700)

    @property
    def redacted_database_url(self) -> str:
        return redact_database_url(self.database_url)


def redact_database_url(database_url: str) -> str:
    parsed = urlsplit(database_url)
    if not parsed.netloc:
        return database_url
    host_part = parsed.hostname or ""
    if parsed.port:
        host_part = f"{host_part}:{parsed.port}"
    if parsed.username:
        host_part = f"{parsed.username}:***@{host_part}"
    return urlunsplit((parsed.scheme, host_part, parsed.path, parsed.query, parsed.fragment))


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default
