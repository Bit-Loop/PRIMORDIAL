SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    methodology TEXT NOT NULL,
    profile TEXT NOT NULL,
    autonomy_mode TEXT NOT NULL,
    status TEXT NOT NULL,
    title TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    handle TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    profile TEXT NOT NULL,
    in_scope INTEGER NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_assets (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    asset TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    target_id TEXT,
    session_id TEXT,
    phase TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    role TEXT NOT NULL,
    methodology TEXT NOT NULL,
    required_capabilities_json TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    status TEXT NOT NULL,
    priority INTEGER NOT NULL,
    risk_tier TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL,
    requires_approval INTEGER NOT NULL,
    provider_route TEXT,
    provider_model TEXT,
    parent_task_id TEXT,
    latest_run_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_runs (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    role TEXT NOT NULL,
    provider_route TEXT NOT NULL,
    model_name TEXT NOT NULL,
    cold_path INTEGER NOT NULL,
    heartbeat_at TEXT,
    lease_expires_at TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    trace_summary TEXT NOT NULL,
    error TEXT,
    metadata_json TEXT NOT NULL,
    FOREIGN KEY(task_id) REFERENCES tasks(id)
);

CREATE TABLE IF NOT EXISTS task_handoffs (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    source_agent TEXT NOT NULL,
    destination_agent TEXT NOT NULL,
    reason TEXT NOT NULL,
    expected_output_type TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    hypothesis TEXT,
    budget TEXT,
    deadline_at TEXT,
    status TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    consumed_at TEXT,
    FOREIGN KEY(task_id) REFERENCES tasks(id)
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    task_id TEXT,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    verification_status TEXT NOT NULL,
    confidence REAL NOT NULL,
    freshness REAL NOT NULL,
    artifact_path TEXT,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    task_id TEXT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    confidence REAL NOT NULL,
    freshness REAL NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS interests (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    status TEXT NOT NULL,
    confidence REAL NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    confidence REAL NOT NULL,
    verification_status TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS memory_entries (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    layer TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    confidence REAL NOT NULL,
    freshness REAL NOT NULL,
    status TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    id TEXT PRIMARY KEY,
    action_kind TEXT NOT NULL,
    verdict TEXT NOT NULL,
    reason TEXT NOT NULL,
    target_id TEXT,
    task_id TEXT,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS primitives (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    version TEXT NOT NULL,
    description TEXT NOT NULL,
    capability_tags_json TEXT NOT NULL,
    allowed_phases_json TEXT NOT NULL,
    runtime TEXT NOT NULL,
    risk_tier TEXT NOT NULL,
    side_effect_level TEXT NOT NULL,
    required_secrets_json TEXT NOT NULL,
    input_schema_json TEXT NOT NULL,
    output_schema_json TEXT NOT NULL,
    timeout_seconds INTEGER NOT NULL,
    retry_policy_json TEXT NOT NULL,
    evidence_adapter TEXT,
    sandbox_profile TEXT,
    healthcheck TEXT,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    task_id TEXT,
    target_id TEXT,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    channel TEXT NOT NULL,
    event_type TEXT NOT NULL,
    summary TEXT NOT NULL,
    target_id TEXT,
    task_id TEXT,
    finding_id TEXT,
    status TEXT NOT NULL,
    urgency TEXT NOT NULL,
    dedupe_key TEXT,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS external_sync_jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    summary TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notion_pages (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    page_type TEXT NOT NULL,
    title TEXT NOT NULL,
    external_id TEXT NOT NULL,
    status TEXT NOT NULL,
    url TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS discord_deliveries (
    id TEXT PRIMARY KEY,
    notification_id TEXT NOT NULL,
    status TEXT NOT NULL,
    external_ref TEXT,
    attempts INTEGER NOT NULL,
    last_error TEXT,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    id TEXT PRIMARY KEY,
    task_id TEXT,
    run_id TEXT,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    summary TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_traces (
    id TEXT PRIMARY KEY,
    task_id TEXT,
    role TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    target_id TEXT,
    task_id TEXT,
    summary TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operator_messages (
    id TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    target_id TEXT,
    model TEXT,
    body TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS remote_provider_costs (
    id TEXT PRIMARY KEY,
    route TEXT NOT NULL,
    model TEXT NOT NULL,
    task_id TEXT,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    estimated_cost_usd REAL NOT NULL DEFAULT 0.0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_remote_costs_created_at ON remote_provider_costs(created_at);

CREATE INDEX IF NOT EXISTS idx_tasks_target_status ON tasks(target_id, status);
CREATE INDEX IF NOT EXISTS idx_task_runs_task_status ON task_runs(task_id, status);
CREATE INDEX IF NOT EXISTS idx_evidence_target ON evidence(target_id);
CREATE INDEX IF NOT EXISTS idx_notes_target ON notes(target_id);
CREATE INDEX IF NOT EXISTS idx_interests_target ON interests(target_id);
CREATE INDEX IF NOT EXISTS idx_memory_target_layer ON memory_entries(target_id, layer);
CREATE INDEX IF NOT EXISTS idx_notifications_status ON notifications(status, created_at);
CREATE INDEX IF NOT EXISTS idx_sync_status ON external_sync_jobs(status, created_at);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
CREATE INDEX IF NOT EXISTS idx_operator_messages_created_at ON operator_messages(created_at);
"""
