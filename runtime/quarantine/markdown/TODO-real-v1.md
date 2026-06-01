---
origin: source_markdown
migration_ref: catalog/policies/markdown_migrations.yaml
ingest_allowed: false
operational_retrieval_allowed: false
---

# Primordial Real V1 TODO

Last updated: 2026-05-04
Status: active implementation list

## 2026-05-08 File Review Tracker

Scope: active product source, docs, manifests, tests, tracked operator artifacts, and generated web entrypoints. Excludes runtime chat logs, model blobs, cache directories, and dependency folders. Legacy backup/demo files already staged for deletion remain deleted.

Status legend:
- `fixed` means reviewed and changed in this pass.
- `reviewed` means checked in this pass without code changes.
- `tracked` means inventoried for the production-grade sweep and left for deeper follow-up.
- `removed` means deleted as demo, skeleton, or generated residue.

Removed in this pass:
- `claud__--resume_79312534-d772-4ad8-bd5f-9bd5f6b1738f` - removed; empty tracked skeleton artifact.
- `gui/Primordial Control Plane.html` - removed; obsolete standalone CDN/Babel demo shell.
- `findings/targets/target/findings.md` - removed; generic generated empty target artifact.
- `findings/targets/target/evidence.md` - removed; generic generated empty target artifact.
- `findings/targets/target/guidance.md` - removed; generic generated empty target artifact.
- `findings/notion/target/notion-export.md` - removed; generic generated empty Notion export.

Root, packaging, and CI:
- `AGENTS.md` - reviewed.
- `PLANS.md` - tracked.
- `README.md` - fixed; removed retired sample-scope documentation.
- `TODO-real-v1.md` - fixed; this tracker section.
- `ai-agent-current-context.md` - tracked.
- `ai-agent-prd.md` - tracked.
- `cli.py` - tracked.
- `.github/workflows/v1-gate.yml` - tracked.
- `.gitignore` - tracked.
- `package.json` - fixed; removed unused topojson dependency.
- `package-lock.json` - fixed; removed unused topojson dependency tree.
- `pyproject.toml` - reviewed through compile/test commands.
- `vite.config.mjs` - reviewed through web build.

Catalogs, manifests, and skills:
- `catalog/agent_skills/operator_intent.yaml` - tracked.
- `catalog/capabilities/semantics.yaml` - tracked.
- `catalog/heuristics/exploit_research.yaml` - tracked.
- `catalog/heuristics/service_discovery.yaml` - tracked.
- `catalog/heuristics/web_discovery.yaml` - tracked.
- `catalog/intents/ad_lab.yaml` - tracked.
- `catalog/intents/credential_validation.yaml` - tracked.
- `catalog/intents/exploit_research_allowed.yaml` - tracked.
- `catalog/intents/htb_lab.yaml` - tracked.
- `catalog/intents/recon_only.yaml` - tracked.
- `catalog/intents/web_triage.yaml` - tracked.
- `catalog/playbooks/lab/htb_windows_flag_collection.yaml` - tracked.
- `catalog/playbooks/recon/ad_enumeration.yaml` - tracked.
- `manifests/ad-enumeration.json` - tracked.
- `manifests/behavior-review.json` - tracked.
- `manifests/caido-search.json` - tracked.
- `manifests/chain-review.json` - tracked.
- `manifests/claude-review.json` - tracked.
- `manifests/content-discovery.json` - tracked.
- `manifests/credentialed-access-check.json` - tracked.
- `manifests/discord-alert.json` - tracked.
- `manifests/dns-enumeration.json` - tracked.
- `manifests/finding-verification.json` - tracked.
- `manifests/http-probe.json` - tracked.
- `manifests/hypothesis-analysis.json` - tracked.
- `manifests/kerberos-attack-check.json` - tracked.
- `manifests/kerberos-user-discovery.json` - tracked.
- `manifests/memory-compactor.json` - tracked.
- `manifests/notion-sync.json` - tracked.
- `manifests/poc-applicability-validation.json` - tracked.
- `manifests/searchsploit-research.json` - tracked.
- `manifests/tcp-service-discovery.json` - tracked.
- `skills/caido-httpql/SKILL.md` - reviewed against Caido memory defaults.

Docs, examples, and durable finding artifacts:
- `docs/FLOOR_PLAN.md` - tracked.
- `docs/HOW_PRIMORDIAL_WORKS.md` - tracked.
- `docs/capability_catalog.md` - tracked.
- `docs/operator_intent.md` - tracked.
- `docs/structured_autonomy.md` - tracked.
- `examples/methodology/web_review.md` - tracked.
- `findings/README.md` - tracked.
- `findings/targets/pirate.htb/evidence.md` - reviewed as real target artifact, not demo.
- `findings/targets/pirate.htb/findings.md` - reviewed as real target artifact, not demo.
- `findings/targets/pirate.htb/guidance.md` - reviewed as real target artifact, not demo.
- `findings/notion/pirate.htb/notion-export.md` - reviewed as real target export, not demo.

GUI source and web bundle:
- `gui/app.jsx` - reviewed through Chromium smoke.
- `gui/atoms.jsx` - reviewed through Chromium smoke.
- `gui/caido.jsx` - reviewed through endpoint smoke; kept replay/status flow safe when credentials are absent.
- `gui/chat.jsx` - fixed; removed unsafe HTML rendering and fake fallback response.
- `gui/dashboard.jsx` - fixed; removed unsafe HTML rendering and fake sparkline generation.
- `gui/interests.jsx` - reviewed through Chromium smoke.
- `gui/map.jsx` - fixed; removed hardcoded demo graph/path/time and remote atlas fetches.
- `gui/notion.jsx` - reviewed through Chromium smoke.
- `gui/pair.jsx` - fixed; removed unsafe HTML rendering and fake fallback response.
- `gui/theme.css` - reviewed through Chromium screenshot.
- `gui/tweaks-panel.jsx` - reviewed through generated bundle build.
- `primordial/core/web/frontend/index.html` - reviewed through Vite build.
- `primordial/core/web/static/index.html` - fixed by generated build output.
- `primordial/core/web/static/assets/index-C-VKFVnF.js` - fixed by generated build output.
- `primordial/core/web/static/assets/index-DGX6F3pQ.css` - reviewed by generated build output.

Scripts:
- `scripts/bootstrap-v1.sh` - tracked.
- `scripts/build-gui.mjs` - fixed; removed unused topojson global injection.
- `scripts/setup_ollama_models.sh` - tracked; not run because model setup was intentionally deferred.
- `scripts/stop-bootstrap-postgres.sh` - tracked.
- `scripts/v1-gate.sh` - reviewed; safe non-model gate wording preserved.

Python package and runtime:
- `primordial/__init__.py` - tracked.
- `primordial/config.py` - tracked.
- `primordial/runtime.py` - tracked.
- `primordial/cli.py` - tracked.
- `primordial/adapters/__init__.py` - tracked.
- `primordial/adapters/caido.py` - reviewed against credential-safe Caido behavior.
- `primordial/adapters/discord.py` - tracked.
- `primordial/adapters/notion.py` - tracked.
- `primordial/app/__init__.py` - tracked.
- `primordial/app/runtime.py` - reviewed through web/API tests.
- `primordial/core/__init__.py` - tracked.
- `primordial/core/config.py` - tracked.
- `primordial/core/credentials.py` - reviewed through credential tests.
- `primordial/core/doctor.py` - tracked.
- `primordial/core/findings_context.py` - reviewed through findings-context tests.
- `primordial/core/skills.py` - tracked.
- `primordial/core/startup.py` - tracked.
- `primordial/core/autonomy/__init__.py` - tracked.
- `primordial/core/autonomy/failure.py` - tracked.
- `primordial/core/autonomy/methodology.py` - tracked.
- `primordial/core/autonomy/proposals.py` - tracked.
- `primordial/core/autonomy/safety.py` - tracked.
- `primordial/core/autonomy/tools.py` - tracked.
- `primordial/core/catalog/__init__.py` - tracked.
- `primordial/core/catalog/capabilities.py` - tracked.
- `primordial/core/catalog/heuristics.py` - tracked.
- `primordial/core/catalog/interpolation.py` - tracked.
- `primordial/core/catalog/loader.py` - tracked.
- `primordial/core/catalog/parsers.py` - tracked.
- `primordial/core/catalog/playbooks.py` - tracked.
- `primordial/core/domain/__init__.py` - tracked.
- `primordial/core/domain/constants.py` - tracked.
- `primordial/core/domain/enums.py` - tracked.
- `primordial/core/domain/models.py` - tracked.
- `primordial/core/events/__init__.py` - tracked.
- `primordial/core/events/bus.py` - tracked.
- `primordial/core/intent/__init__.py` - tracked.
- `primordial/core/intent/models.py` - tracked.
- `primordial/core/intent/registry.py` - tracked.
- `primordial/core/modules/__init__.py` - tracked.
- `primordial/core/modules/registry.py` - tracked.
- `primordial/core/orchestration/__init__.py` - tracked.
- `primordial/core/orchestration/policy.py` - tracked.
- `primordial/core/orchestration/verifier.py` - tracked.
- `primordial/core/orchestration/workflow.py` - reviewed through targeted web/runtime tests.
- `primordial/core/primitives/__init__.py` - tracked.
- `primordial/core/primitives/catalog.py` - tracked.
- `primordial/core/providers/__init__.py` - tracked.
- `primordial/core/providers/lmstudio.py` - tracked; no live provider calls run.
- `primordial/core/providers/model_eval.py` - tracked; no model benchmark run.
- `primordial/core/providers/ollama.py` - tracked; no live provider calls run.
- `primordial/core/providers/router.py` - tracked.
- `primordial/core/providers/scheduler.py` - tracked.
- `primordial/core/recovery/__init__.py` - tracked.
- `primordial/core/recovery/crash_journal.py` - tracked.
- `primordial/core/recovery/resume_tracker.py` - tracked.
- `primordial/core/storage/__init__.py` - tracked.
- `primordial/core/storage/runtime.py` - fixed; production wording for synthetic cleanup paths.
- `primordial/core/storage/schema.py` - reviewed through isolated Postgres tests.
- `primordial/core/validation/__init__.py` - tracked.
- `primordial/core/validation/registry.py` - tracked.
- `primordial/core/validation/validators.py` - tracked.
- `primordial/core/web/__init__.py` - tracked.
- `primordial/core/web/app.py` - fixed; removed pre-escaped HTML events and demo map coordinates.
- `primordial/core/web/server.py` - fixed; continuous tick runner can restart after stop.
- `primordial/core/workers/__init__.py` - tracked.
- `primordial/core/workers/broker.py` - tracked.
- `primordial/modes/__init__.py` - tracked.
- `primordial/modes/security/__init__.py` - tracked.
- `primordial/modes/security/execution.py` - tracked.
- `primordial/modes/security/memory.py` - tracked.
- `primordial/modes/security/methodology.py` - tracked.
- `primordial/modes/security/module.py` - tracked.
- `primordial/ui/__init__.py` - tracked.
- `primordial/ui/textual_app.py` - tracked.

Tests:
- `tests/__init__.py` - reviewed through test discovery.
- `tests/postgres_bootstrap.py` - reviewed through isolated Postgres tests.
- `tests/support.py` - reviewed through targeted tests.
- `tests/test_caido_and_skills.py` - reviewed through endpoint smoke.
- `tests/test_cli_web_alias.py` - tracked.
- `tests/test_credentials.py` - tracked.
- `tests/test_findings_context.py` - tracked.
- `tests/test_model_eval.py` - tracked; not run live against providers.
- `tests/test_module_registry.py` - tracked.
- `tests/test_operator_intent_catalog_autonomy.py` - tracked.
- `tests/test_policy.py` - tracked.
- `tests/test_postgres_storage.py` - reviewed through isolated Postgres tests.
- `tests/test_provider_router.py` - tracked.
- `tests/test_runtime_integration.py` - reviewed through selected non-model runtime tests.
- `tests/test_verifier.py` - tracked.
- `tests/test_web_console.py` - fixed; added checks for retired demo tokens.
- `tests/test_worker_broker.py` - tracked.
- `tests/test_workflow.py` - tracked.

## Locked Decisions

- Remove all fixture, bootstrap, sample, and scaffold behavior from the active product path. Completed for the active GUI path.
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
- Remove scaffold and fixture wording from the README and operator docs.
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

1. Remove fixture/bootstrap/sample code paths.
2. Switch active runtime storage from SQLite to Postgres.
3. Add real Ollama provider adapter and health checks.
4. Replace synthetic execution with real primitives for the first HTB/web lane.
5. Add real Caido integration.
6. Add real Notion integration.
7. Add real Discord integration.
8. Add secure bearer-token auth and token persistence for the web GUI.
9. Harden memory, verification, and contradiction handling.
10. Validate the first real workflow against `pirate.htb`.
