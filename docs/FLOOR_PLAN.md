# Primordial Codebase Floor Plan

This file is a practical map for editing Primordial. Use it when you need to know where a feature lives, where to add behavior, and what files should usually change together.

## Top-Level Layout

- `cli.py`
  - Thin repo-root wrapper for the real CLI.
  - Use this when running commands from the project root.

- `primordial/cli.py`
  - Main command-line interface.
  - Add new CLI commands here only after the runtime already exposes the behavior.

- `primordial/app/runtime.py`
  - Main application composition root and service facade.
  - Most UI, CLI, and web actions should call methods here rather than reaching into storage or workers directly.
  - This file currently does a lot and should be treated carefully.

- `primordial/core/`
  - Reusable control-plane systems: storage, orchestration, policy, providers, credentials, web, validation, recovery, events, and domain models.

- `primordial/modes/security/`
  - Authorized security-testing behavior.
  - Add cyber methodology, primitive execution, evidence generation, and memory behavior here.

- `primordial/adapters/`
  - External integrations: Notion, Discord, Caido.

- `primordial/gui/launcher.py`
  - Local Tk GUI launcher.
  - It mirrors many web console controls but should call runtime methods, not duplicate business logic.

- `primordial/core/web/`
  - Local web app and static HTML/CSS/JS console.

- `manifests/`
  - Primitive manifests.
  - Add or update tool/skill capability metadata here.

- `tests/`
  - Unit and integration tests.
  - Add tests when changing runtime behavior, web endpoints, workflow planning, policy, storage, credentials, or primitive behavior.

- `findings/`
  - Durable operator-facing findings workspace.
  - This is runtime data, not core source code. Agents may read bounded guidance from here.

- `runtime/`
  - SQLite DB, crash journal, and runtime state.
  - Do not manually edit unless debugging with backups.

- `primordial/n8n-master/`
  - Reference/vendor material. Avoid broad searches through this directory unless intentionally comparing against n8n.

## Common Edit Paths

### Add A Runtime Feature

Edit in this order:

1. Add domain types if needed in `primordial/core/domain/enums.py` or `primordial/core/domain/models.py`.
2. Add durable persistence in `primordial/core/storage/schema.py` and `primordial/core/storage/runtime.py` if the feature needs storage.
3. Add facade methods in `primordial/app/runtime.py`.
4. Expose through CLI in `primordial/cli.py` if useful.
5. Expose through web in `primordial/core/web/app.py` if operator-facing.
6. Expose through GUI in `primordial/gui/launcher.py` if operator-facing.
7. Add tests under `tests/`.

Rule: UI layers should call `PrimordialRuntime`, not storage internals, whenever practical.

### Add A Web Console Control

Files usually involved:

- `primordial/core/web/app.py`
  - Add or update API endpoint.

- `primordial/core/web/static/index.html`
  - Add the control markup.

- `primordial/core/web/static/app.js`
  - Wire button/form behavior and state rendering.

- `primordial/core/web/static/styles.css`
  - Add visual styles.

- `tests/test_web_console.py`
  - Add endpoint-level test. Prefer testing the Python web app directly rather than browser automation.

Keep the web app thin. Business logic should stay in `PrimordialRuntime`.

### Add A GUI Control

File usually involved:

- `primordial/gui/launcher.py`

Editing pattern:

1. Add Tk variables in `PrimordialLauncher.__init__`.
2. Add UI widgets in the appropriate `_build_*_tab` method.
3. Add a small event handler method.
4. Use `_run_background()` for work that may touch models, storage, network, tools, or filesystem.
5. Call runtime facade methods under `self._runtime_lock`.
6. Queue UI updates through `self._queue` if a background thread needs to update widgets.

Do not update Tk widgets directly from background threads.

### Add A Target Or Scope Feature

Runtime files:

- `primordial/app/runtime.py`
  - `register_target()`
  - `import_scope()`
  - `import_scope_payload()`
  - `scope_payload()`
  - `remove_target()`

Web files:

- `primordial/core/web/app.py`
  - `/api/targets`
  - `/api/scope/import`
  - `/api/scope`

GUI files:

- `primordial/gui/launcher.py`
  - Scope Management block and target import helpers.

Tests:

- `tests/test_web_console.py`
  - Web target registration and scope import tests.

### Add Or Change Credentials

Files:

- `primordial/core/credentials.py`
  - Credential store behavior and redacted status.

- `primordial/app/runtime.py`
  - Runtime methods such as `set_*_credentials()` and `credentials_payload()`.

- `primordial/core/web/app.py`
  - Web credential endpoints.

- `primordial/gui/launcher.py`
  - GUI credential controls.

- `tests/test_credentials.py`
  - Storage, redaction, and migration tests.

Rule: Never expose full credential values in dashboard payloads, logs, tests, chat, or status messages.

### Add A Primitive Or Tool

Files:

- `manifests/<primitive>.json`
  - Capability, risk, side effects, schema, timeout, and evidence metadata.

- `primordial/modes/security/execution.py`
  - Add execution handler if the primitive needs custom behavior.

- `primordial/core/validation/validators.py`
  - Add validation if task payloads need structural or safety checks.

- `tests/test_runtime_integration.py`
  - Add a test that proves normalized evidence is produced and unsafe behavior is gated.

Rules:

- Model should reason about capability, not raw shell chaos.
- Raw tool output should become normalized evidence, interests, artifacts, or notes.
- DoS, flooding, destructive behavior, and unbounded brute force should stay blocked.

### Add A New Task Type

Files:

- `primordial/core/domain/enums.py`
  - Add `TaskKind` if needed.

- `primordial/modes/security/methodology.py`
  - Add methodology blueprint/capability mapping.

- `primordial/core/orchestration/workflow.py`
  - Add planning rules and state transitions.

- `primordial/modes/security/execution.py`
  - Add `_handle_<task_kind>()`.

- `manifests/`
  - Add required primitive manifest(s).

- `tests/test_workflow.py`
  - Planning behavior.

- `tests/test_runtime_integration.py`
  - Execution and evidence behavior.

### Add AI Model Behavior

Files:

- `primordial/core/providers/router.py`
  - Decide which route a task should use.

- `primordial/core/providers/scheduler.py`
  - Concurrency and model scheduling constraints.

- `primordial/core/providers/ollama.py`
  - Ollama API calls, warm/unload/list/generate.

- `primordial/app/runtime.py`
  - Model role config, model role persistence, operator AI, worker AI generation.

- `primordial/modes/security/execution.py`
  - Worker prompts and task-specific AI use.

Rules:

- Keep AI calls bounded and task-specific.
- Do not use deterministic status rendering when the operator asks for actual reasoning.
- Store AI chat in DB and `chat_log/`.
- Keep mission-critical code/exploit work on the configured cold/code route unless intentionally changed.

### Add Notion, Discord, Or Caido Behavior

Files:

- `primordial/adapters/notion.py`
  - Notion API page/database write behavior.

- `primordial/adapters/discord.py`
  - Discord delivery behavior.

- `primordial/adapters/caido.py`
  - Caido GraphQL integration.

- `primordial/app/runtime.py`
  - Integration payloads and credential setter methods.

- `primordial/modes/security/execution.py`
  - Task-side requests to queue sync jobs or notifications.

- `tests/test_caido_and_skills.py`
- `tests/test_credentials.py`
- `tests/test_web_console.py`

## Current UI Edit Areas

### Local GUI

Main file:

- `primordial/gui/launcher.py`

Tabs:

- Main: web server controls, target/scope management, tips/guidance, workflow controls, output.
- Agent Monitor: traces, task runs, worker AI notes.
- AI Thinking: model reasoning stream with separators and speaker/model metadata.
- Operator Chat: local model Q&A.
- Counts: dashboard and runtime counts.
- Config: model roles and credential controls.

Known issue:

- This file is too large. Future work should split it into smaller view/controller modules.

### Web App

Files:

- `primordial/core/web/app.py`
- `primordial/core/web/static/index.html`
- `primordial/core/web/static/app.js`
- `primordial/core/web/static/styles.css`

Major UI areas:

- Controls and execution mode.
- Counts/dashboard.
- Credentials.
- Integrations.
- Model roles.
- Operator AI.
- Tips and target guidance.
- Scope and targets.
- Tasks and task detail.
- Audit records.

Known issue:

- `app.js` is too large and should eventually be split by domain: state/api, controls, scope, credentials, models, chat/guidance, records.

## Test Map

- `tests/test_web_console.py`
  - Web endpoints, model controls, credentials, target registration, scope import, operator chat, guidance.

- `tests/test_runtime_integration.py`
  - Real runtime behavior for primitives, recon, searchsploit, AD/Kerberos, credentialed access.

- `tests/test_workflow.py`
  - Planning and workflow transitions.

- `tests/test_policy.py`
  - Approval and safety gates.

- `tests/test_provider_router.py`
  - Model route decisions.

- `tests/test_credentials.py`
  - Secret storage and redaction.

- `tests/test_findings_context.py`
  - Durable findings/guidance workspace.

- `tests/test_caido_and_skills.py`
  - Caido and skill surfaces.

Run all tests:

```bash
python3 -m unittest discover -s tests -t . -v
```

## Refactor Priorities

1. Split `primordial/gui/launcher.py` into smaller tab modules.
2. Split `primordial/core/web/static/app.js` into focused modules.
3. Split `primordial/modes/security/execution.py` into primitive handlers by family.
4. Move repetitive API action response wiring into helpers or a small router table.
5. Add explicit schema/version migrations for storage.
6. Add richer server-side continuous mode if browser-driven continuous ticks become unreliable.
7. Add a stronger typed API contract for web/GUI payloads.

