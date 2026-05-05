# Primordial Real V1 TODO

Last updated: 2026-05-04
Status: active implementation list

## Locked Decisions

- Remove all demo, bootstrap, sample, and scaffold behavior from the active product path.
- Treat `PostgreSQL + pgvector` as the canonical live store.
- Standardize local model serving on `Ollama`.
- Start the first real workflow lane with:
  - HTTP probe
  - content discovery
  - parameter mining
  - JS extraction
  - Caido evidence ingest/search
  - finding verification
- Implement real integrations for:
  - Caido
  - Notion
  - Discord
- Defer Anthropic/Claude API execution until the tool substrate is proven to work as intended.
- Secure the web GUI with bearer-token auth that is remembered securely and handled without fragile shortcuts.

## Model Storage

- Default local model path: `PRIMORDIAL/AI_MODELS/ollama`
- Required follow-up:
  - ensure model blobs are excluded from version control
  - set `OLLAMA_MODELS` to that path in runtime/dev docs
  - make runtime health checks verify Ollama availability and required models

## Phase 1: Remove Scaffold Paths

- Remove the legacy bootstrap action from the CLI and web action surface. Completed.
- Remove runtime sample/bootstrap helpers from the active code path.
- Remove sample scope wiring from config defaults.
- Remove scaffold/demo wording from the README and operator docs.
- Replace synthetic empty-state assumptions with explicit operator-facing setup flows.
- Replace any stubbed or fake records that exist only to make the UI look populated.

Acceptance criteria:
- No active CLI or web command seeds fake targets, fake evidence, fake notes, or fake findings.
- A fresh runtime starts empty and explains what real setup steps are required.
- No production code path depends on the retired sample scope file. Completed.

## Phase 2: Production Storage Backbone

- Replace SQLite as the active runtime store with PostgreSQL.
- Add `pgvector` support for note, evidence, finding, and memory retrieval.
- Preserve filesystem artifact storage on NVMe with SQL metadata references.
- Add startup schema initialization/migration for Postgres.
- Define clear config for:
  - database DSN
  - vector support
  - artifact root
  - export/archive paths
- Keep SQLite only if needed for portable exports or debug bundles, never as the live store.

Acceptance criteria:
- The active runtime boots against Postgres only.
- Core entities persist correctly across restart:
  - targets
  - scope assets
  - tasks
  - task runs
  - evidence
  - notes
  - interests
  - findings
  - memory entries
  - policy decisions
  - notifications
  - sync state
- Retrieval metadata is persisted alongside canonical records.

## Phase 3: Local Model Runtime via Ollama

- Add a real Ollama provider adapter for:
  - `local-fast`
  - `local-deep`
  - `local-code`
  - `local-compact`
  - optional cold reviewers
- Add runtime health checks for Ollama reachability and required model presence.
- Add model preload and residency settings for the two-lane runtime.
- Add scheduler awareness for:
  - hot-path GPU residency
  - compact/background CPU lane
  - cold-path reviewer jobs
- Add provider result normalization with traceable prompts, outputs, timing, and token/cost metadata where available.

Target model set:
- `gemma4:e4b`
- `deepseek-r1:8b`
- `qwen3-coder-next:q4_K_M`
- `phi4-reasoning`
- optional:
  - `gemma3:27b`
  - `qwen2.5:32b`
  - `deepseek-r1:32b`

Acceptance criteria:
- The runtime can verify model availability before scheduling work.
- Real model calls replace placeholder reasoning behavior.
- Scheduler policy respects hot-path vs cold-path separation.

## Phase 4: Real Primitive Execution Lane

- Remove synthetic outputs from the security executor.
- Implement primitive runner contracts that call real tools instead of fabricating evidence.
- Keep capability-based routing and manifest-driven onboarding intact.
- Add install-state and health-state checks per primitive.
- Add deterministic output normalization and evidence extraction for the first lane.

First primitive set:
- HTTP probe
- content discovery
- parameter mining
- JS extraction
- Caido search / ingest
- finding verification

Required execution features:
- timeout handling
- retries with policy bounds
- risk-tier enforcement
- artifact capture
- structured evidence extraction
- runner traces

Acceptance criteria:
- Recon and analysis evidence comes from actual tool execution.
- Artifacts are stored on disk and referenced in canonical storage.
- The orchestrator only sees normalized evidence and primitive metadata.

## Phase 5: Caido Integration

- Add a real Caido adapter instead of placeholder semantics.
- Ingest/search Caido traffic and replay-linked evidence.
- Bind evidence to:
  - replay IDs
  - request/response fingerprints
  - target scope
  - timestamps
- Keep Caido as the source of truth for relevant HTTP workflow artifacts.
- Build the integration boundary so a narrow JS/TS adapter is allowed if that is the best Caido path.

Acceptance criteria:
- The runtime can ingest and search Caido-backed evidence for a target.
- Evidence lineage references Caido IDs directly.
- Findings and notes can link back to Caido artifacts.

## Phase 6: Notion Integration

- Replace fake local Notion page generation with real Notion API sync.
- Preserve local structured storage as canonical.
- Build idempotent per-target subtree syncing:
  - target root
  - overview
  - notes
  - evidence links
  - findings
  - open hypotheses
  - next actions
- Track sync jobs, external IDs, retries, and failures.
- Avoid pushing raw noisy artifacts directly into Notion.

Acceptance criteria:
- A real target sync creates or updates a stable Notion subtree.
- Sync is idempotent and failure-aware.
- Internal records track external page IDs and delivery state.

## Phase 7: Discord Integration

- Replace fake local Discord delivery records with real Discord delivery.
- Implement high-signal filtering only.
- Add deduplication and rate limiting.
- Include target/task/finding references in outgoing alerts.
- Persist delivery attempts and failures.

Acceptance criteria:
- Approval requests and high-signal finding events are delivered to Discord.
- Repeated low-value events do not spam the channel.
- Delivery history remains auditable in the control plane.

## Phase 8: Web GUI Security

- Add bearer-token auth to the web GUI and API.
- Store the token securely and remember it across restarts.
- Do not store plaintext tokens in repo files or casual runtime dumps.
- Preferred implementation:
  - generated token
  - system keyring or equivalent secure local secret storage
  - hashed fingerprint in app state only where needed
- Add explicit login/logout/rotation flow.
- Bind secure defaults:
  - local-only by default unless intentionally exposed
  - constant-time token comparison
  - request auth on all API routes
  - audit auth failures

Acceptance criteria:
- The web console requires auth for control actions and state reads.
- Token rotation works.
- Token persistence survives restart without unsafe plaintext storage in the project tree.

## Phase 9: Workflow and Memory Hardening

- Replace summary-only compaction with contradiction-aware memory logic.
- Enforce promotion/demotion/invalidation rules from the PRD/current-context docs.
- Trigger memory jobs on:
  - task completion
  - large evidence ingestion
  - context pressure
  - periodic timers
- Add verifier checks for:
  - unsupported claims
  - duplicate work
  - retry storms
  - loop patterns
  - confidence inflation
- Add richer context slicing for:
  - task context
  - shared working context
  - episodic memory
  - semantic memory

Acceptance criteria:
- Durable facts always link back to evidence and metadata.
- Contradictions can supersede prior facts explicitly.
- Verification checks run without relying only on another model.

## Phase 10: HTB First Real Workflow

- Use `pirate.htb` / `10.129.47.117` as the first live HTB test target.
- Ensure scope tracking works in:
  - CLI
  - TUI
  - web GUI
- Run the first real workflow lane against that target using real primitives and real evidence capture.
- Record failures, blockers, and missing capabilities as first-class notes/issues rather than hiding them.

Acceptance criteria:
- The target exists as a real in-scope HTB asset in canonical storage.
- Recon/analysis tasks run with real tool output.
- Operator surfaces show real evidence, notes, interests, and task lineage for this target.

## Explicit Deferrals

- Anthropic/Claude API execution
  - do not implement until the local tool substrate and control-plane behavior are proven sound
- broad heterogeneous tool onboarding
  - keep v1 narrow and operationally real
- mature exploit automation
  - only after bounded verification and evidence quality are stable

## Immediate Execution Order

1. Remove demo/bootstrap/sample code paths.
2. Switch active runtime storage from SQLite to Postgres.
3. Add real Ollama provider adapter and health checks.
4. Replace synthetic execution with real primitives for the first HTB/web lane.
5. Add real Caido integration.
6. Add real Notion integration.
7. Add real Discord integration.
8. Add secure bearer-token auth and token persistence for the web GUI.
9. Harden memory, verification, and contradiction handling.
10. Validate the first real workflow against `pirate.htb`.
