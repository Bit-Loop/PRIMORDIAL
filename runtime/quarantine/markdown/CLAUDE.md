---
origin: source_markdown
migration_ref: catalog/policies/markdown_migrations.yaml
ingest_allowed: false
operational_retrieval_allowed: false
---

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Primordial Is

Primordial is a **local-first control plane** for AI-assisted authorized security testing (HackerOne, Hack The Box, pentesting engagements). It is a deterministic workflow system that uses LLMs at bounded decision points — not an always-on chat agent or a monolithic prompt session.

The architectural invariants that must never be violated:
- No risky action without explicit policy evaluation.
- No durable fact without evidence, provenance, confidence, and freshness metadata.
- AI output is advisory — deterministic checks must still gate consequential decisions.
- No agent receives the full engagement history by default; context is sliced per task.
- Scope must be explicit before any task runs.

## Commands

### Run Tests
```bash
python3 -m unittest discover -s tests -t . -v     # full suite
python3 -m unittest tests.test_workflow -v         # single module
python3 -m unittest tests.test_policy -v
python3 -m unittest tests.test_runtime_integration -v
python3 -m unittest tests.test_web_console -v
```

### Syntax Checks
```bash
python3 -m py_compile primordial/app/runtime.py primordial/core/orchestration/workflow.py primordial/modes/security/execution.py
node --check primordial/core/web/static/app.js
```

### CLI (from project root)
```bash
python3 cli.py show
python3 cli.py scope
python3 cli.py tick
python3 cli.py run-loop --cycles 3
python3 cli.py compact
python3 cli.py process-queues
python3 cli.py add-target pirate.htb --profile hack_the_box --asset pirate.htb --asset 10.129.47.117
python3 cli.py approve <task_id>
python3 cli.py ask "status and next step" --target pirate.htb
python3 cli.py tui
python3 cli.py web --port 1337
python3 cli.py models warm --keep-alive 8h
```

### Local Model Setup
```bash
mkdir -p /home/bitloop/Desktop/PRIMORDIAL/AI_MODELS/ollama
export OLLAMA_MODELS=/home/bitloop/Desktop/PRIMORDIAL/AI_MODELS/ollama
export OLLAMA_MAX_LOADED_MODELS=4
ollama serve
bash scripts/setup_ollama_models.sh   # or pull models manually
```

## Architecture

### Layer Map (edit lowest first, always)

```
enums / domain models         primordial/core/domain/
storage schema + queries      primordial/core/storage/schema.py
                              primordial/core/storage/runtime.py  (dev: runtime/primordial.db)
runtime facade (main API)     primordial/app/runtime.py           ← PrimordialRuntime
workflow / planning           primordial/core/orchestration/workflow.py
policy / safety gating        primordial/core/orchestration/policy.py
behavior verifier             primordial/core/orchestration/verifier.py
task execution + evidence     primordial/modes/security/execution.py
task blueprints               primordial/modes/security/methodology.py
memory compaction             primordial/modes/security/memory.py
model routing + scheduling    primordial/core/providers/router.py
                              primordial/core/providers/scheduler.py
                              primordial/core/providers/ollama.py
worker dispatch               primordial/core/workers/broker.py
credentials                   primordial/core/credentials.py
findings/guidance workspace   primordial/core/findings_context.py
web API                       primordial/core/web/app.py
web frontend                  primordial/core/web/static/  (index.html, app.js, styles.css)
local Tk GUI                  primordial/gui/launcher.py
adapters                      primordial/adapters/notion.py
                              primordial/adapters/discord.py
                              primordial/adapters/caido.py
primitive manifests           manifests/*.json
```

All UI and CLI code should call **`PrimordialRuntime`** methods, not storage internals or execution handlers directly.

### Execution Model: The Tick

Everything runs through bounded ticks, not an unbounded loop:

```
run_tick()
  → resume waiting tasks
  → inspect targets and plan missing methodology tasks
  → run behavior verifier checks
  → execute ready tasks (up to max_executions)
  → process external queues
```

Continuous mode is just the UI repeatedly triggering bounded ticks at a configured interval. It is still tick-based and policy-gated.

### AI Model Roles

Four configured routes; route work based on role, not habit:

| Route | Purpose | Typical model |
|---|---|---|
| `local_fast` | Hot-path orchestration, broad analysis | `gemma3:12b` (GPU) |
| `local_deep` | Harder reasoning, operator Q&A | `deepseek-r1:8b` (GPU) |
| `local_code` | PoC research, exploit adaptation | `qwen2.5-coder:7b` (GPU, cold) |
| `local_compact` | Memory compaction, verifier checks | `phi4-mini` (CPU) |

Optional `remote_premium` route (Claude/OpenAI) is policy-disabled by default.

Role categories (for routing decisions): deep reasoning · fast planning · code synthesis · compact summarization · tool selection · validation · recovery and retry · CPU-friendly lightweight tasks · GPU-friendly heavy inference tasks.

Hardware-aware routing rules:
- Heavy inference stays on GPU routes (`local_fast`, `local_deep`, `local_code`).
- Compaction, classification, and lightweight checks use CPU routes (`local_compact`).
- Role switching must be explicit, logged, and evidence-based — avoid silent role drift.
- Track why a model or role was chosen for every non-trivial dispatch.

### Task Planning → Execution → Evidence Flow

```
register_target() / import_scope()
  → workflow.py plans tasks based on target state + evidence
  → policy.py gates each action (ALLOW / NEEDS_APPROVAL / DENY)
  → provider router chooses model route
  → execution.py handler runs, normalizes tool output
  → evidence / notes / interests / artifacts written to DB
  → memory compaction + Notion sync + Discord notifications queued
```

### Policy and Safety Gates

Policy evaluates tasks against: scope binding, risk tier, methodology phase, autonomy mode, approval requirements, timeout/request limits, and agent safety approval metadata. Policy decisions use structured metadata — not vague AI text.

For PoC execution to proceed without human approval, **all** of the following must be true:
- `PRIMORDIAL_AUTONOMY_MODE` is `supervised_auto` or `high_autonomy`
- `PRIMORDIAL_ALLOW_EXPLOITATIVE_ACTIONS=1` is set
- Task carries an `agent_safety_approval` from the behavior verifier
- Scope, evidence linkage, non-DoS classification, request limits, and timeout limits are explicit in that approval

### Primitive Manifests (`manifests/*.json`)

Each tool is described by a manifest (capability tags, risk tier, side effects, input/output schema, timeout, evidence adapter, etc.). Agents reason about capability classes — not raw shell commands. Available primitives include: `tcp-service-discovery`, `dns-enumeration`, `http-probe`, `content-discovery`, `ad-enumeration`, `kerberos-*`, `searchsploit-research`, `finding-verification`, `memory-compactor`, `caido-search`, `notion-sync`, `discord-alert`, `claude-review`, and others.

### Durable State vs. Derived Views

| Canonical (source of truth) | Derived / auxiliary view |
|---|---|
| `runtime/primordial.db` (SQLite) | `findings/targets/<target>/*.md` |
| DB task/evidence/note records | Notion pages |
| DB notification records | Discord messages |
| DB chat records | `chat_log/YYYY-MM-DD/*.json` |

Do not let Notion or Discord drift into being treated as authoritative.

### Key Known Weak Points (don't make them worse)

- `primordial/app/runtime.py` is already a large god object — keep new logic in the correct lower layer.
- `primordial/gui/launcher.py` is too large — do not add more business logic here.
- `primordial/core/web/static/app.js` is too large — keep it thin.
- `primordial/modes/security/execution.py` mixes many primitive families — new handlers go in dedicated `_handle_<task_kind>()` methods.
- Web routing in `PrimordialWebApp.dispatch()` is a long if/else chain — avoid lengthening it without reason.
- There is no web authentication layer.

## Correct Change Sequence

For any non-trivial change, follow this order:

1. Add/update domain types (`core/domain/enums.py`, `core/domain/models.py`)
2. Add/update storage schema and queries if durable state is needed
3. Add/update runtime facade method in `primordial/app/runtime.py`
4. Add/update workflow/policy/execution/verifier logic
5. Expose via CLI (`primordial/cli.py`) and/or web (`core/web/app.py`) and/or GUI (`gui/launcher.py`)
6. Add tests in the same patch
7. Run narrow tests, then full suite, then syntax checks

**Never** start at step 5 for a behavior change. **Never** bypass `PolicyEngine` for risky actions.

## Generation Safety (critical)

When targets can change IPs, every read of evidence, interests, findings, or tasks must ask: **"Should this be filtered to the current active-IP generation?"**

Key fields: `target.metadata.active_ip`, `active_ip_generation`. Mixing historical evidence into current-generation reasoning is a correctness bug, not just a minor issue.

## Testing Requirements

Rules:
- New behavior must ship with tests. Changed behavior must update tests. Regressions are unacceptable.
- Tests must be written to be CI-ready (suitable for GitHub Actions without major restructuring).
- Prefer repeatable, deterministic tests over ad hoc manual checks.
- Critical workflows must have integration tests, not just unit tests.
- External integrations must have mocked tests plus real-world smoke tests where safe.
- Test failures are first-class signals — do not ignore them.
- Validate both success and failure paths in every test.
- Add fixtures and helper utilities where they reduce duplication (see `tests/support.py`).

Required coverage areas: core orchestration · policy gates · state transitions · memory and evidence handling · model routing · primitive execution · adapter behavior · metadata tracking · methodology updates · error handling and recovery.

Tests should create temporary runtime directories — do not use the live `runtime/primordial.db` in tests.

### Test File Map

| Test file | What it covers |
|---|---|
| `tests/test_workflow.py` | Planning and workflow transitions |
| `tests/test_policy.py` | Approval and safety gates |
| `tests/test_runtime_integration.py` | Primitive execution, evidence write-back |
| `tests/test_web_console.py` | Web endpoints, model controls, credentials, scope import |
| `tests/test_provider_router.py` | Model route decisions |
| `tests/test_credentials.py` | Secret storage and redaction |
| `tests/test_findings_context.py` | Durable findings/guidance workspace |
| `tests/test_caido_and_skills.py` | Caido and skill surfaces |
| `tests/test_worker_broker.py` | Worker dispatch and broker behavior |
| `tests/test_model_eval.py` | Model evaluation logic |
| `tests/test_verifier.py` | Loop/claim/evidence-quality detection |

## What to Avoid

- Building business logic in GUI or web JS — it belongs in `PrimordialRuntime` or lower.
- Using raw tool output directly in reasoning without normalization into evidence records.
- Adding `sleep`-based polling loops — everything is tick-driven.
- Routing AI calls without bounded context slices; agents should not receive full history.
- Writing credentials, tokens, or raw secrets to logs, chat payloads, tests, or dashboard responses.
- Making AI output authoritative over deterministic checks.
- Searching broadly through `primordial/n8n-master/` — it is reference/vendor material.

## Hard Boundaries

- **DDoS is always forbidden.** Never propose, automate, optimize, or assist with DDoS in any form.
- Only support targets explicitly authorized within scope. If a request could impact a real third-party system outside authorized scope, stop and warn before proceeding.
- If scope is ambiguous, ask for clarification before proceeding.
- Prefer safe, reversible, measurable changes over cleverness. When a task has risk, call it out plainly.

## How to Approach This Codebase

Treat the repository like a real system, not a pile of files. State matters.

- Surface contradictions between docs and code; inspect the code, note the mismatch, propose a correction. The PRD (`ai-agent-prd.md`) is a reference starting point — prefer current repository state when they conflict.
- Question assumptions. Prefer explicitness, determinism, and traceability over magic.
- Identify edge cases, failure modes, and hidden coupling before editing.
- When the design is weak, say so and explain why. Do not flatter the design.
- When multiple valid paths exist, compare tradeoffs and recommend one.
- Before changing anything, inspect relevant files, understand the current architecture, and identify dependencies.
- Preserve existing style and patterns unless there is a clear reason to change them.
- Make the smallest change that actually solves the problem. Prefer surgical refactors over large rewrites.
- If a change touches multiple subsystems, describe the dependency chain before editing.
- If a file needs substantial restructuring, explain the plan first.
- Never silently overwrite meaningfully different logic.

## File Handling Rules

- Read before you write. Always.
- When editing, preserve intent, naming, and structure where possible.
- Keep changes localized. Update related files together only when required by the change.
- If you create a new file, explain why it belongs in the repository and where it fits in the layer map.
- If you remove or rename something, explain the downstream impact before doing it.
- Treat configuration, schema, and workflow files as high-impact assets — changes there ripple.
- Do not scatter logic across random files when an existing module is the right home.
- Keep generated artifacts and runtime outputs out of source unless explicitly required.
- Use clear, predictable filenames and directory placement.
- Do not introduce duplicate concepts under different names.

## Operational Priority Order

When tradeoffs arise, resolve them in this order:

1. Evidence
2. Control
3. Traceability
4. Correctness
5. Maintainability
6. Performance

## Markdown File Governance

**`ai-agent-prd.md` is read-only.** Never modify, overwrite, rename, or delete it.

Only these four markdown files may be created or modified (beyond `CLAUDE.md` itself):

| File | Purpose |
|---|---|
| `living-context.md` | Current system state, active targets, recent changes, session continuity |
| `problem-tracking.md` | Bugs, blockers, failed attempts, unresolved issues (each entry needs description, impact, status, attempted fixes, next action) |
| `cyber-methodology-guidelines.md` | Canonical structured hacking methodology, living and evidence-driven |
| `system-architecture.md` | Component boundaries, data flow, orchestration logic, model routing strategy |

No other `.md` files may be created. Do not generate temporary markdown files, alternate versions, or duplicate content across files. Before writing to any of these, read current contents and update incrementally — do not overwrite.

## Required Trace Metadata

Every AI model call and task execution must capture:

- model name, role name, task type, stage
- pass/fail result, confidence, outcome notes, reason for success or failure
- token or cost estimate (when available), latency, retry count
- evidence quality assessment

This metadata feeds model routing improvements, methodology prioritization, and behavior verification.

## Tooling Inventory

The system's tool awareness must be dynamic, not static:

- Maintain a current inventory of primitives, skills, adapters, and scripts.
- Detect when tooling changes, disappears, or becomes stale — mark the capability as unavailable.
- Tool awareness must feed into task generation, methodology selection, and model routing.
- Do not assume a tool exists unless its manifest and health-check have been verified.

## Resource and Budget Enforcement

Each task must declare an expected cost range and timeout threshold. The system enforces:

- Hard token usage limits per task.
- Execution time ceilings per task and total runtime per workflow.
- Termination + failure recording when limits are exceeded; retries must be explicitly justified.
- No runaway loops or infinite retries.

## Failure Containment and State Integrity

- Failures are isolated to the smallest possible scope — a failing task must not corrupt global state, methodology, or unrelated branches.
- Partial outputs must be clearly marked as incomplete.
- If system state becomes inconsistent: halt progression, require operator intervention or rollback.
- Invalid state transitions must be rejected. Validate state before and after critical operations.
- Corrupted or incomplete state must not be used for further decisions.

## Startup and Resume Behavior

On startup: load prior state, validate integrity, rebuild active context. If state is inconsistent, enter safe mode and require an operator decision. Resume must not duplicate tasks or corrupt evidence lineage.

## Multistage Pipelining and Concurrency

The orchestrator must manage multiple tasks, phases, and targets in parallel when safe:

- Work is scheduled as a pipeline of bounded stages — not one giant undifferentiated loop.
- Each stage must have explicit inputs, outputs, exit conditions, and evidence requirements.
- Parallel work is allowed only when dependencies do not conflict.
- Shared-state access must be deterministic and guarded against race conditions.
- When tasks block on external services, the orchestrator continues other safe work instead of idling.
- The orchestrator must detect bottlenecks, stalls, and deadlocks, and know when to pause, split, merge, reprioritize, or abandon a branch.
- Prefer many small, verifiable steps over fewer large opaque ones.
- Every concurrent action must still produce lineage, timestamps, and evidence links. Concurrency must never destroy traceability.
- If a task is not safe to parallelize, keep it serial.

## Evidence-Based Progression

Progress only when the evidence supports it. Do not advance a workflow stage on vibes, guesses, or incomplete output.

- Track pass/fail rates for both models and roles.
- Track latency, retries, truncation, failures, confidence, and task completion quality.
- Track which tools, models, and workflows produce useful evidence versus dead ends.
- Use these metrics to improve scheduling, routing, and methodology selection.
- If a model or role performs poorly on a task class, record it and adjust future routing.
- If a strategy repeatedly fails, de-prioritize it or retire it.

## AI Control Plane Standards

The control plane is the most critical part of the infrastructure — treat it as a first-class system, not an auxiliary feature:

- Architecture must be clean, explicit, and maintainable.
- Code must be well commented where comments add real value: explain intent, invariants, and non-obvious logic. Avoid noisy or redundant comments.
- Modules must be organized for long-term readability and systems-level clarity.
- Favor deterministic behavior, strong boundaries, traceable state, and minimal ambiguity. Do not build cleverness that obscures control.
- Every important action must be explainable, inspectable, and auditable.
- The control plane must remain operator-directed and policy-bound at all times.
- Every important subsystem must be understandable by a careful engineer reading the source. The codebase should feel like disciplined systems engineering, not improvisation.

## Methodology System

Methodology is not static documentation. It is a living, versioned, state-aware system that evolves during operation. Treat it as: structured, mutable, evidence-driven, versioned over time, and linked to real findings and outcomes.

**Structure:** Represent methodology as structured phases, not paragraphs. Each phase must define: name, goal, entry conditions, exit conditions, tasks, expected evidence types, and common failure modes. Phases map to real workflow states: recon → analysis → validation → chaining.

**Mutability:** Methodology may be modified at runtime when a task repeatedly fails, a better path is discovered, or evidence contradicts assumptions. When modifying: log the change, explain why, preserve the previous version. Treat changes like commits, not edits. Never override operator intent silently.

**Evidence-driven evolution:** Methodology updates must be justified by evidence. Mark techniques as low-value or deprecated when they produce no results. Elevate productive techniques. Never fabricate effectiveness.

**Task generation:** Tasks must be derived from the current methodology state and anchored to a phase and goal. Each task must reference its parent phase, define expected output/evidence, and define a success/failure condition. Do not generate tasks that are not anchored to a phase.

**Dead-end detection:** If multiple tasks in a phase fail without useful evidence, mark the branch as exhausted and suggest a pivot or phase transition. Do not loop indefinitely on unproductive tasks.

**Branching and hypotheses:** When evidence suggests a new direction, create a methodology branch labeled with a hypothesis. Track branches separately from the main flow. Allow rollback if the branch fails.

**Operator control:** The operator may modify methodology manually, approve/reject methodology changes, or freeze methodology for a run. Never override operator intent silently.

**Exporting:** Methodology must be exportable as clean human-readable notes and as a structured format (JSON/YAML). Exports should capture what worked, what failed, and why decisions were made, optimized for reuse on future targets.

**Notes integration:** Notes inform methodology and methodology changes should update notes. Operate a continuous refinement loop: execute task → collect evidence → evaluate usefulness → update notes → adjust methodology if needed. This loop must be explicit and traceable.

**Testing philosophy:** Prioritize logic flaws and access control issues over noisy automated scans. Favor manual validation paths when evidence suggests a vulnerability. Treat tools as assistants, not decision-makers.

**Threat modeling:** Incorporate structured threat modeling (e.g., STRIDE) during the analysis phase. Map discovered assets to potential threat categories to generate targeted testing tasks.

**Safety:** Methodology must respect all policy constraints. DDoS and any destructive or out-of-scope activity must never appear as a task. If a methodology step violates policy, reject it and explain why.

**Definition of success:** Methodology becomes more efficient over time, fewer dead-end tasks are generated, evidence quality improves, and future runs benefit from past learning.

## Determinism Constraints

- Orchestration decisions must be deterministic given the same state and inputs.
- Model outputs are nondeterministic — they must be normalized and validated before use in decisions.
- The same task should produce comparable outcomes across retries unless inputs change.
- If outputs vary significantly across retries, flag the instability and reduce reliance on that path.

## Primitive Execution Safety

- All primitives run within defined boundaries: timeouts, rate limits, and scope constraints.
- Treat all primitive output as untrusted input. Never assume tool output is correct, complete, or safe.
- Validate and normalize all primitive outputs before they are used in reasoning, evidence records, or notes.
