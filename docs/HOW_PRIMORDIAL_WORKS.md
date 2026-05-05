# How Primordial Works

Primordial is a local-first control plane for AI-assisted authorized security testing. It is not designed as one giant always-on prompt. It is a deterministic workflow system that uses models at bounded decision points, stores durable state locally, and exposes operator controls through CLI, GUI, and web interfaces.

## Core Idea

The program is built around a few invariants:

- Scope must be explicit.
- Policy gates risky actions.
- Tasks are durable records, not transient chat messages.
- Evidence is stored with provenance.
- AI workers receive bounded context slices.
- Notion and Discord are external views/alerts, not the source of truth.
- Continuous mode should be bounded repeated ticks, not uncontrolled background hacking.

## Runtime Assembly

The main assembly point is:

- `primordial/app/runtime.py`

`PrimordialRuntime` wires together:

- `RuntimeStore`
  - SQLite-backed durable operational state.

- `CredentialStore`
  - Local credential storage and redacted status.

- `PrimitiveCatalog`
  - Loads primitive manifests from `manifests/`.

- `WorkflowOrchestrator`
  - Plans and executes bounded task ticks.

- `PolicyEngine`
  - Decides whether actions are allowed, denied, or need approval.

- `ProviderRouter`
  - Chooses model route: local fast, local deep, local code, compact, or remote premium.

- `ModelScheduler`
  - Controls route concurrency and scheduling.

- `BehaviorVerifier`
  - Looks for loops, unsupported claims, and suspicious agent behavior.

- `RuntimeSkillRegistry`
  - Loads local skills.

- `FindingsContextService`
  - Manages durable per-target files under `findings/`.

- `ModuleRegistry`
  - Lazy-loads security mode, Notion, Discord, and Caido modules.

The runtime exposes facade methods such as `run_tick()`, `register_target()`, `import_scope_payload()`, `ask_operator_ai()`, `warm_model_routes()`, `update_execution_mode()`, and credential setters. UI and CLI layers should prefer these methods.

## Storage And State

Runtime storage lives in:

- `primordial/core/storage/schema.py`
- `primordial/core/storage/runtime.py`

The development store is SQLite under `runtime/primordial.db`.

Important records include:

- targets
- scope assets
- sessions
- tasks
- task runs
- evidence
- notes
- interests
- findings
- memory entries
- policy decisions
- traces
- artifacts
- notifications
- external sync jobs
- model/settings state

The database is the operational source of truth. UI panels, Notion exports, chat logs, and markdown guidance are derived or auxiliary views.

## Scope And Targets

Targets are registered through:

- `PrimordialRuntime.register_target()`
- `PrimordialRuntime.import_scope()`
- `PrimordialRuntime.import_scope_payload()`

Each target has:

- handle
- display name
- profile, such as `hack_the_box` or `hackerone`
- in-scope flag
- assets
- metadata

Scope can be added from:

- CLI
- GUI Scope Management
- Web Scope section
- JSON or line-based scope files

The workflow planner only has useful work to do after targets and assets exist.

## Execution Model

The central execution unit is a tick:

```text
operator/UI/continuous loop
        |
        v
PrimordialRuntime.run_tick()
        |
        v
WorkflowOrchestrator.tick()
```

A tick does this:

1. Resume due waiting tasks.
2. Inspect targets.
3. Plan missing methodology tasks.
4. Run behavior verifier checks.
5. Execute ready tasks up to `max_executions`.
6. Process external queues.

Tick mode means work only happens when an operator presses a button or runs a CLI command.

Continuous mode means a UI repeatedly triggers bounded ticks at a configured interval. It is still tick-based and policy-gated.

## Workflow Planning

Planning lives in:

- `primordial/core/orchestration/workflow.py`
- `primordial/modes/security/methodology.py`

The orchestrator plans based on target state and evidence. Examples:

- If no evidence exists, plan recon.
- If DNS is exposed, plan DNS enumeration.
- If LDAP/Kerberos/SMB are exposed, plan AD/Kerberos tasks.
- If HTTP is live, plan web content discovery.
- If evidence density justifies it, plan analysis or exploit research.
- If behavior looks suspicious, plan behavior verification.

The planner should avoid repeating completed work unless evidence changes or a retry/resume rule says it should.

## Policy And Safety

Policy lives in:

- `primordial/core/orchestration/policy.py`

Policy evaluates tasks and primitive actions against:

- scope
- risk tier
- methodology phase
- autonomy mode
- approval requirements
- exploitative-action settings
- bounded timeout/request constraints
- agent safety approval metadata

Risky exploitation and PoC execution should not happen merely because an AI suggested it. The system needs explicit scope, task metadata, policy pass, and usually approval.

## Workers And Primitives

Primitive execution lives mainly in:

- `primordial/modes/security/execution.py`

The current implementation uses an in-process worker runner and a primitive executor. Tasks are mapped to handlers such as recon, service discovery, DNS enumeration, AD enumeration, Kerberos discovery, searchsploit research, memory compaction, and behavior review.

External tools are represented by manifests:

- `manifests/*.json`

The model should reason over capability and metadata, not arbitrary shell commands. Outputs should become normalized evidence, interests, notes, findings, artifacts, or notifications.

## AI Model Use

AI providers and routing live in:

- `primordial/core/providers/router.py`
- `primordial/core/providers/scheduler.py`
- `primordial/core/providers/ollama.py`
- `primordial/app/runtime.py`

Configured roles:

- `local_fast`
  - Hot-path orchestration and broad analysis.

- `local_deep`
  - Harder reasoning and operator Q&A.

- `local_code`
  - Mission-critical code, exploit research, PoC adaptation.

- `local_compact`
  - Memory compaction, lightweight verification, background classification.

AI is used for:

- operator questions
- bounded worker reviews
- analysis summaries
- exploit research summaries
- behavior review
- memory compaction and guidance

AI is not supposed to be a permanent full-context chatbot. Persistent knowledge should be stored as structured records and per-target guidance.

## Operator Chat And AI Thinking

Operator chat is handled through:

- `PrimordialRuntime.ask_operator_ai()`
- GUI Operator Chat tab
- Web Operator AI section

Messages are stored in:

- runtime database
- `chat_log/YYYY-MM-DD/*.json`

The AI Thinking tab in the GUI displays model-generated reasoning artifacts, worker review notes, AI traces, and non-deterministic operator model answers. Deterministic status replies are intentionally excluded.

## Findings Context And Guidance

Durable target context lives under:

- `findings/targets/<target>/guidance.md`
- `findings/targets/<target>/findings.md`
- `findings/targets/<target>/evidence.md`
- `findings/notion/<target>/notion-export.md`

Managed by:

- `primordial/core/findings_context.py`

Guidance is used as bounded permanent context for agents. It is intended for:

- target-specific methodology notes
- operator preferences
- things to avoid
- known assumptions
- useful target facts
- feedback from previous runs

Do not use guidance as a dump for raw scanner output.

## Integrations

### Notion

Files:

- `primordial/adapters/notion.py`

Purpose:

- Publish readable per-target notes/findings/guidance into Notion.
- Mirror local canonical records.

Notion is not the source of truth.

### Discord

Files:

- `primordial/adapters/discord.py`

Purpose:

- Deliver high-signal notifications such as finding candidates, PoC research events, approval needs, and workflow failures.

Discord is not an audit log.

### Caido

Files:

- `primordial/adapters/caido.py`

Purpose:

- Connect to Caido GraphQL for web traffic, replays, findings, and HTTP testing evidence references.

Caido should remain the web-testing backbone where applicable.

## Interfaces

### CLI

File:

- `primordial/cli.py`

Use for:

- automation
- smoke tests
- debugging
- simple operator workflows

The CLI should call `PrimordialRuntime`, not implement separate business logic.

### GUI

File:

- `primordial/gui/launcher.py`

Use for:

- local desktop control
- web server start/stop
- scope management
- guidance editing
- model controls
- credentials
- agent monitor
- AI Thinking stream
- operator chat

The GUI uses background threads and a queue to avoid blocking Tk. Do not update Tk widgets directly from background threads.

### Web App

Files:

- `primordial/core/web/app.py`
- `primordial/core/web/static/index.html`
- `primordial/core/web/static/app.js`
- `primordial/core/web/static/styles.css`

Use for:

- browser-based control
- target/scope import
- credentials
- model role selection
- operator chat
- guidance editing
- task inspection
- records and audit review

The web app is intentionally local and simple. It currently does not implement authentication, multi-user sessions, or server-sent updates.

## How UI Sync Works

The GUI and web app sync by reading and writing the same runtime store through `PrimordialRuntime`.

Examples:

- Execution mode is stored in `app_settings`.
- Model roles are stored in `app_settings`.
- Credentials are stored in the credential store.
- Scope is stored in target and scope-asset tables.
- Guidance is stored in per-target markdown files and exposed through runtime payloads.
- Tasks, traces, and evidence are stored in SQLite.

The GUI and web app do not directly talk to each other. They mirror each other by sharing the same runtime and storage.

## Critical Data Flow Example

```text
Operator imports target
        |
        v
Runtime registers target and assets
        |
        v
Tick plans recon/service tasks
        |
        v
Policy validates task
        |
        v
Provider router chooses model route
        |
        v
Worker executes primitive
        |
        v
Evidence/artifacts/notes/interests written
        |
        v
Memory/guidance/export/notification queues update
        |
        v
GUI/Web/CLI render refreshed state
```

## Current Strengths

- Real durable state model rather than mock UI state.
- Good separation between runtime facade, workflow, storage, policy, providers, and adapters.
- Useful test coverage for web endpoints, workflow, policy, credentials, target import, and primitive behavior.
- Explicit model-role routing.
- Bounded tick architecture is safer than a persistent autonomous prompt.
- Findings/guidance workspace is a good bridge between human notes and agent context.

## Current Weak Points

- `PrimordialRuntime` is becoming a god object.
- `primordial/gui/launcher.py` is too large.
- `primordial/core/web/static/app.js` is too large.
- `primordial/modes/security/execution.py` is too large and mixes many primitive families.
- Web routing in `PrimordialWebApp.dispatch()` is a long if/else chain.
- Continuous mode is currently UI-driven, not a durable server-side scheduler.
- SQLite is useful for v1, but production architecture still points toward Postgres/pgvector.
- There is no web authentication layer.
- There is no formal API schema.
- The n8n reference tree pollutes searches unless excluded.

## Safe Development Rules

- Do not bypass `PolicyEngine` for risky work.
- Do not write secrets to logs, chat, dashboard payloads, or tests.
- Do not make Notion or Discord canonical storage.
- Do not load the whole findings folder into prompts.
- Do not turn continuous mode into an unbounded loop.
- Do not expose arbitrary shell execution to AI workers.
- Add tests for new runtime/web/workflow/policy behavior.

