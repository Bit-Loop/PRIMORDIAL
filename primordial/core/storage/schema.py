SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    methodology TEXT NOT NULL,
    profile TEXT NOT NULL,
    autonomy_mode TEXT NOT NULL,
    status TEXT NOT NULL,
    title TEXT NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    handle TEXT NOT NULL,
    display_name TEXT NOT NULL,
    profile TEXT NOT NULL,
    in_scope BOOLEAN NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE(profile, handle)
);

CREATE TABLE IF NOT EXISTS scope_assets (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    target_id TEXT REFERENCES targets(id) ON DELETE SET NULL,
    session_id TEXT REFERENCES sessions(id) ON DELETE SET NULL,
    phase TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    role TEXT NOT NULL,
    methodology TEXT NOT NULL,
    required_capabilities JSONB NOT NULL,
    evidence_refs JSONB NOT NULL,
    metadata JSONB NOT NULL,
    status TEXT NOT NULL,
    priority INTEGER NOT NULL,
    risk_tier TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL,
    requires_approval BOOLEAN NOT NULL,
    provider_route TEXT,
    provider_model TEXT,
    parent_task_id TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    latest_run_id TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS task_runs (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    role TEXT NOT NULL,
    provider_route TEXT NOT NULL,
    model_name TEXT NOT NULL,
    cold_path BOOLEAN NOT NULL,
    heartbeat_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    trace_summary TEXT NOT NULL,
    error TEXT,
    metadata JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS task_handoffs (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    source_agent TEXT NOT NULL,
    destination_agent TEXT NOT NULL,
    reason TEXT NOT NULL,
    expected_output_type TEXT NOT NULL,
    evidence_refs JSONB NOT NULL,
    hypothesis TEXT,
    budget TEXT,
    deadline_at TIMESTAMPTZ,
    status TEXT NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    task_id TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    verification_status TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    freshness DOUBLE PRECISION NOT NULL,
    artifact_path TEXT,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    task_id TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    freshness DOUBLE PRECISION NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS interests (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence_refs JSONB NOT NULL,
    status TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL,
    evidence_refs JSONB NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    verification_status TEXT NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_entries (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    layer TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence_refs JSONB NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    freshness DOUBLE PRECISION NOT NULL,
    status TEXT NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    id TEXT PRIMARY KEY,
    action_kind TEXT NOT NULL,
    verdict TEXT NOT NULL,
    reason TEXT NOT NULL,
    target_id TEXT REFERENCES targets(id) ON DELETE SET NULL,
    task_id TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS primitives (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    version TEXT NOT NULL,
    description TEXT NOT NULL,
    capability_tags JSONB NOT NULL,
    allowed_phases JSONB NOT NULL,
    runtime TEXT NOT NULL,
    risk_tier TEXT NOT NULL,
    side_effect_level TEXT NOT NULL,
    required_secrets JSONB NOT NULL,
    input_schema JSONB NOT NULL,
    output_schema JSONB NOT NULL,
    timeout_seconds INTEGER NOT NULL,
    retry_policy JSONB NOT NULL,
    evidence_adapter TEXT,
    sandbox_profile TEXT,
    healthcheck TEXT,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    target_id TEXT REFERENCES targets(id) ON DELETE SET NULL,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    channel TEXT NOT NULL,
    event_type TEXT NOT NULL,
    summary TEXT NOT NULL,
    target_id TEXT REFERENCES targets(id) ON DELETE SET NULL,
    task_id TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    finding_id TEXT REFERENCES findings(id) ON DELETE SET NULL,
    status TEXT NOT NULL,
    urgency TEXT NOT NULL,
    dedupe_key TEXT,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS external_sync_jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    summary TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL,
    metadata JSONB NOT NULL,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS notion_pages (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    page_type TEXT NOT NULL,
    title TEXT NOT NULL,
    external_id TEXT NOT NULL,
    status TEXT NOT NULL,
    url TEXT NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS discord_deliveries (
    id TEXT PRIMARY KEY,
    notification_id TEXT NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    external_ref TEXT,
    attempts INTEGER NOT NULL,
    last_error TEXT,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    id TEXT PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id) ON DELETE CASCADE,
    run_id TEXT REFERENCES task_runs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    summary TEXT NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_traces (
    id TEXT PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    target_id TEXT REFERENCES targets(id) ON DELETE SET NULL,
    task_id TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    summary TEXT NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS operator_messages (
    id TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    target_id TEXT REFERENCES targets(id) ON DELETE SET NULL,
    model TEXT,
    body TEXT NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS remote_provider_costs (
    id TEXT PRIMARY KEY,
    route TEXT NOT NULL,
    model TEXT NOT NULL,
    task_id TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    estimated_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS model_eval_runs (
    id TEXT PRIMARY KEY,
    providers JSONB NOT NULL,
    models JSONB NOT NULL,
    recommendations JSONB NOT NULL,
    artifacts JSONB NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS model_eval_role_metrics (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES model_eval_runs(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    aggregate_score DOUBLE PRECISION NOT NULL,
    pass_rate DOUBLE PRECISION NOT NULL,
    fail_rate DOUBLE PRECISION NOT NULL,
    hallucination_count INTEGER NOT NULL,
    hallucination_rate DOUBLE PRECISION NOT NULL,
    over_refusal_rate DOUBLE PRECISION NOT NULL,
    correct_refusal_rate DOUBLE PRECISION NOT NULL,
    unsafe_compliance_failures INTEGER NOT NULL,
    top_failure_modes JSONB NOT NULL,
    avg_latency_sec DOUBLE PRECISION,
    avg_tokens_sec DOUBLE PRECISION,
    best_context_length INTEGER,
    quantization TEXT,
    params TEXT,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS record_embeddings (
    id TEXT PRIMARY KEY,
    target_id TEXT REFERENCES targets(id) ON DELETE CASCADE,
    record_type TEXT NOT NULL,
    record_id TEXT NOT NULL,
    embedding_model TEXT NOT NULL,
    embedding_dim INTEGER NOT NULL,
    embedding vector NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(record_type, record_id, embedding_model)
);

CREATE INDEX IF NOT EXISTS idx_targets_profile_handle ON targets(profile, handle);
CREATE INDEX IF NOT EXISTS idx_remote_costs_created_at ON remote_provider_costs(created_at);
CREATE INDEX IF NOT EXISTS idx_model_eval_role_created ON model_eval_role_metrics(role, created_at);
CREATE INDEX IF NOT EXISTS idx_model_eval_run_created ON model_eval_runs(created_at);
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
CREATE INDEX IF NOT EXISTS idx_record_embeddings_record ON record_embeddings(record_type, record_id);
"""
