---
origin: source_markdown
migration_ref: catalog/policies/markdown_migrations.yaml
ingest_allowed: false
operational_retrieval_allowed: false
---

# How A Human Should Work On Primordial

This guide is for a human engineer changing Primordial safely. It is not an architecture overview. It is the practical workflow to follow before, during, and after editing the codebase.

Read these first:

1. `README.md`
2. `docs/HOW_PRIMORDIAL_WORKS.md`
3. `docs/FLOOR_PLAN.md`
4. `ai-agent-current-context.md`
5. `ai-agent-prd.md`

If you skip those, you will usually make the wrong change in the wrong layer.

## What Primordial Is

Primordial is a deterministic control plane for authorized security workflows.

It is not:

- one giant prompt
- a freeform chatbot that should directly mutate runtime state
- a pure UI app
- a pile of shell scripts

The important pattern is:

1. deterministic planning
2. deterministic policy admission
3. bounded execution
4. evidence write-back
5. bounded AI review/proposal
6. deterministic verification

When you modify the codebase, preserve that order.

## Core Rules

- Treat `PrimordialRuntime` as the main facade for operator-facing behavior.
- Treat the database as the source of truth.
- Treat `target.metadata.active_ip` and `active_ip_generation` as safety-critical.
- Do not let UI code invent business logic that belongs in runtime, workflow, policy, or execution.
- Do not let AI output become durable truth without deterministic checks and evidence.
- Do not bypass scope, policy, or generation filters to “make it work.”
- Do not mix historical target evidence into current active-IP reasoning.

## Safe Working Environment

Before editing:

1. Work from the repo root: `PRIMORDIAL/`
2. Avoid using the live `runtime/` database for risky experiments.
3. Prefer tests that create temporary runtime directories.
4. Keep a mental distinction between source code and runtime data:
   - source: `primordial/`, `manifests/`, `docs/`, `tests/`
   - runtime data: `runtime/`, `findings/`, `chat_log/`

Useful commands:

```bash
python3 -m unittest discover -s tests -t . -v
python3 -m py_compile primordial/app/runtime.py primordial/core/orchestration/workflow.py primordial/modes/security/execution.py
node --check primordial/core/web/static/app.js
python3 cli.py show
python3 cli.py tick
python3 cli.py ask "status and next step" --target pirate.htb
```

## The Correct Change Workflow

Follow this sequence almost every time:

### 1. Clarify The Change Type

Decide which of these you are doing:

- domain/state change
- workflow/planning change
- policy/safety change
- primitive/tooling change
- AI/model behavior change
- UI/API change
- integration change
- test/debug/observability change

If you cannot classify the change, you are not ready to edit yet.

### 2. Find The Real Authority

Do not start in the UI.

Identify the layer that owns the behavior:

- runtime facade: `primordial/app/runtime.py`
- workflow/planning: `primordial/core/orchestration/workflow.py`
- policy: `primordial/core/orchestration/policy.py`
- verifier: `primordial/core/orchestration/verifier.py`
- task execution and evidence generation: `primordial/modes/security/execution.py`
- task blueprints: `primordial/modes/security/methodology.py`
- provider/model routing: `primordial/core/providers/router.py`
- worker dispatch: `primordial/core/workers/broker.py`
- storage/schema: `primordial/core/storage/`
- web API: `primordial/core/web/app.py`
- web frontend: `primordial/core/web/static/`
- local GUI: `primordial/gui/launcher.py`

### 3. Read The Whole Flow Before Editing

For any non-trivial change, read:

1. where the input enters
2. where the decision is made
3. where state is persisted
4. where UI renders the result
5. which tests already cover it

Example:

If changing target IP behavior, read:

- `runtime.register_target()` / `runtime.update_target_fields()`
- active-IP helpers in `runtime.py`
- generation-aware planning in `workflow.py`
- generation-aware execution filtering in `execution.py`
- web target endpoints in `core/web/app.py`
- GUI target management in `gui/launcher.py`
- related tests in `tests/test_workflow.py` and `tests/test_web_console.py`

### 4. Change The Lowest Correct Layer First

Preferred order:

1. enums / domain models
2. storage
3. runtime/service logic
4. policy / workflow / execution / verifier
5. API
6. UI
7. tests
8. docs

Do not start at step 5 or 6 unless the change is purely cosmetic.

### 5. Keep The Deterministic And AI Paths Separate

When adding model behavior:

- deterministic code should still decide whether an action is admissible
- AI should produce bounded proposals, rankings, summaries, or reviews
- AI output must be structured if it influences workflow
- policy and verification must still be able to reject it

Good:

- AI proposes `candidate_actions`
- workflow checks whether the required primitive exists
- policy decides whether it is allowed

Bad:

- AI says “run this exploit”
- code marks it as a finding
- state changes without deterministic checks

### 6. Preserve Generation Safety

If the target can change IPs, always think about:

- `active_ip`
- `active_ip_generation`
- historical evidence
- stale interests/findings
- operator-facing status answers

If your change reads evidence, interests, findings, or tasks for a target, ask:

“Should this be filtered to the current generation?”

If the answer is yes and you do not filter it, you are probably introducing a bug.

### 7. Update Tests In The Same Patch

Do not add behavior without tests.

Minimum expected coverage:

- workflow changes: `tests/test_workflow.py`
- policy changes: `tests/test_policy.py`
- runtime/execution changes: `tests/test_runtime_integration.py`
- web/API changes: `tests/test_web_console.py`
- model-eval changes: `tests/test_model_eval.py`
- broker/dispatch/verifier changes: dedicated focused tests

### 8. Run Narrow Tests First

Before the full suite, run only the tests that touch your area.

Examples:

```bash
python3 -m unittest tests.test_workflow -v
python3 -m unittest tests.test_policy -v
python3 -m unittest tests.test_runtime_integration -v
python3 -m unittest tests.test_web_console -v
```

Then run the full suite.

### 9. Run Syntax Checks

For Python:

```bash
python3 -m py_compile <files>
```

For web JS:

```bash
node --check primordial/core/web/static/app.js
```

### 10. Confirm Operator Surfaces Still Make Sense

After a backend change, check:

- `cli.py ask "status and next step" --target <target>`
- GUI work status
- web `/api/work-status`
- task detail payloads
- audit/event visibility

If the backend got better but the operator can no longer understand what is happening, the change is incomplete.

## How To Modify Each Major Area

## Runtime Facade

Primary file:

- `primordial/app/runtime.py`

Use this when:

- adding operator-facing methods
- exposing new workflows to CLI/web/GUI
- managing settings, target state, credentials, status payloads, or model roles

Human workflow:

1. Add or adjust a runtime method.
2. Keep it as a facade over deeper services when possible.
3. Avoid pushing too much new business logic into `runtime.py` if it belongs in workflow/policy/execution.
4. Update UI/API callers to use the new method.

Common mistake:

- adding storage logic directly in UI instead of via runtime

## Workflow / Planning

Primary file:

- `primordial/core/orchestration/workflow.py`

Use this when:

- changing what gets planned
- changing when something becomes stale
- adding target methodology state
- changing no-progress or retry behavior

Human workflow:

1. Find the target state inputs.
2. Decide whether the change belongs in:
   - state evaluation
   - candidate action generation
   - task registration
   - execution result persistence
3. Preserve policy and validation calls.
4. Add tests for planning behavior and stale-state behavior.

Common mistake:

- adding one more `_should_plan_*` branch without thinking about methodology state, retries, or current-generation filters

## Policy

Primary file:

- `primordial/core/orchestration/policy.py`

Use this when:

- adding approvals
- changing exploit gating
- adding credential requirements
- enforcing timeout/request ceilings
- classifying side-effect risk

Human workflow:

1. Define the action policy metadata you need.
2. Decide if the check belongs at task level or primitive level.
3. Return `ALLOW`, `NEEDS_APPROVAL`, or `DENY` with a concrete reason.
4. Make sure the reason is operator-readable.
5. Add tests for both allowed and denied paths.

Common mistake:

- making policy depend on vague AI text instead of structured metadata

## Verifier

Primary file:

- `primordial/core/orchestration/verifier.py`

Use this when:

- detecting loops
- detecting stale-state contamination
- detecting unsupported claims
- detecting evidence-quality drift

Human workflow:

1. Define the signal precisely.
2. Prefer deterministic record inspection.
3. Add a dedicated verifier test.
4. Make sure signals are actionable, not just alarming.

Common mistake:

- adding “AI should notice this” instead of teaching the verifier how to detect it structurally

## Execution / Security Mode

Primary file:

- `primordial/modes/security/execution.py`

Use this when:

- adding a task handler
- normalizing tool output
- generating evidence, notes, interests, findings, artifacts
- adding safe AI review on top of deterministic results

Human workflow:

1. Add or adjust `_handle_<task_kind>()`.
2. Make the handler deterministic first.
3. Write normalized evidence and artifacts.
4. Add optional AI review after deterministic outputs exist.
5. Filter target records to the correct active generation.
6. Add integration tests.

Common mistake:

- using raw tool output directly in reasoning or operator answers without normalization

## Methodology Blueprints

Primary file:

- `primordial/modes/security/methodology.py`

Use this when:

- adding a new task kind
- changing default role, phase, capabilities, retries, or priority

Human workflow:

1. Add `TaskKind` first if needed.
2. Add or update the blueprint.
3. Confirm provider routing still makes sense.
4. Confirm worker contracts still make sense.
5. Add or update manifests and execution handlers.

Common mistake:

- giving a task too many required capabilities, which can accidentally force unrelated integrations or secrets

## Worker Dispatch

Primary files:

- `primordial/core/workers/broker.py`
- `primordial/app/runtime.py` worker registration

Use this when:

- changing which worker should run what
- changing lane/contract/processor selection
- improving suitability scoring

Human workflow:

1. Define the worker contract.
2. Register the runner with the correct route and role coverage.
3. Adjust scoring only if you understand the implications for all task kinds.
4. Add broker tests.

Common mistake:

- treating “route” and “worker identity” as the same thing

## Providers / Models

Primary files:

- `primordial/core/providers/router.py`
- `primordial/core/providers/scheduler.py`
- `primordial/core/providers/ollama.py`
- parts of `primordial/app/runtime.py`

Use this when:

- changing which model/lane handles a task
- changing CPU vs GPU behavior
- adding model evaluation logic

Human workflow:

1. Decide whether the change is routing, scheduling, or operator configuration.
2. Keep mission-critical code/PoC reasoning on the intended cold/code path unless intentionally redesigning it.
3. Keep hot-path orchestration responsive.
4. Verify with tests and with model-status commands.

Common mistake:

- routing everything to the same “best” model and destroying concurrency or latency goals

## Web Console

Primary files:

- `primordial/core/web/app.py`
- `primordial/core/web/static/index.html`
- `primordial/core/web/static/app.js`
- `primordial/core/web/static/styles.css`

Human workflow:

1. Add or change the backend endpoint in `app.py`.
2. Keep endpoint logic thin and call runtime.
3. Add or update markup.
4. Update JS state loading and rendering.
5. Add endpoint tests.
6. Run `node --check`.

Common mistakes:

- duplicating runtime logic in JS
- resetting timers or state on every render
- forgetting that web and GUI are supposed to mirror operator controls

## Local GUI

Primary file:

- `primordial/gui/launcher.py`

Human workflow:

1. Add Tk variables.
2. Add widgets to the correct tab.
3. Use background jobs for runtime/model work.
4. Never update Tk widgets from worker threads.
5. Route changes through runtime.
6. Keep GUI and web semantics aligned.

Common mistake:

- blocking the Tk main loop with model or runtime work

## Storage

Primary files:

- `primordial/core/storage/schema.py`
- `primordial/core/storage/runtime.py`

Human workflow:

1. Add schema only when durable state is truly required.
2. Update read/write helpers together.
3. Preserve payload serialization behavior.
4. Update tests that depend on storage shape.

Common mistake:

- storing UI-only transient state durably when it belongs in runtime memory

## Findings Context

Primary files:

- `primordial/core/findings_context.py`
- `findings/targets/<target>/`

Human workflow:

1. Treat this as durable operator guidance, not the primary transactional store.
2. Write bounded, human-readable summaries.
3. Keep canonical state in SQL/runtime records.
4. Use findings context to improve human guidance and bounded AI context.

Common mistake:

- letting markdown files drift away from canonical runtime state

## Common Change Recipes

## Add A New Task

1. Add `TaskKind` in `core/domain/enums.py`
2. Add blueprint in `modes/security/methodology.py`
3. Add planning logic in `workflow.py`
4. Add execution handler in `execution.py`
5. Add or update manifests
6. Update provider routing if needed
7. Update worker contracts if needed
8. Add tests

## Add A New Primitive

1. Add manifest in `manifests/`
2. Add handler or resolver behavior if needed
3. Add policy expectations if it needs secrets or approval
4. Normalize output into evidence
5. Add integration tests

## Add A New Operator Control

1. Add runtime method
2. Add web endpoint or CLI command
3. Add GUI control if appropriate
4. Add tests
5. Confirm work-status / audit visibility

## Change AI Behavior

1. Identify whether it is operator AI or worker AI
2. Keep deterministic source of truth intact
3. Prefer structured output
4. Persist proposal/review metadata
5. Add tests around guardrails or scoring if applicable

## What To Check Before You Commit

- Did I change the correct layer?
- Did I preserve active-IP generation safety?
- Did I accidentally make AI authoritative instead of advisory?
- Did I add deterministic evidence or only text?
- Did I add tests for the changed behavior?
- Did I run syntax checks?
- Did I run the relevant narrow tests?
- Did I run the full suite?
- Will CLI, GUI, and web still present coherent operator state?

## What To Avoid

- editing `runtime/primordial.db` directly to “fix” logic
- building logic only in the GUI or web app
- mixing old target evidence into current planning
- bypassing policy for convenience
- making worker AI mandatory for deterministic task success unless the product requirement truly changed
- adding generic background loops that are not tied to bounded ticks or explicit jobs
- solving capability problems by adding more prose instead of adding structured state

## Recommended Human Workflow In Practice

For most serious changes, use this checklist:

1. Read `README.md`, `docs/HOW_PRIMORDIAL_WORKS.md`, and `docs/FLOOR_PLAN.md`
2. Identify the owning layer
3. Read the full code path
4. Write down the invariant you must preserve
5. Patch the lowest correct layer first
6. Patch callers next
7. Add or update tests immediately
8. Run narrow tests
9. Run syntax checks
10. Run the full test suite
11. Check operator-facing status output
12. Update docs if the shape of the system changed

If you follow that sequence, you will usually modify Primordial correctly. If you start in the UI, skip tests, or let AI text stand in for deterministic state, you will usually break the control plane.
