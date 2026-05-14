# Primordial

Primordial is a local-first control plane for AI-assisted authorized security testing (HackerOne, Hack The Box, pentesting engagements). It is a deterministic workflow system that uses LLMs at bounded decision points — not an always-on chat agent or a monolithic prompt session.

Autonomy is staged behind deterministic policy, durable workflow state, evidence lineage, and explicit operator controls.

## Core Principles

- No risky action without policy evaluation
- No durable memory without evidence and metadata
- No freeform always-on agent loop
- No full-history context by default
- Autonomy must be event-driven, inspectable, and reversible
- PoC execution requires scope binding, non-DoS classification, bounded runtime limits, and approval

## What Is Implemented

- Python package and CLI entrypoint (`cli.py`)
- Durable Postgres store using `psycopg` v3 and required `pgvector`
- Control-plane domain models: targets, tasks, evidence, notes, interests, findings, memory, policy, and traces
- Methodology-aware task planner with phase/exit conditions and dead-end detection
- Autonomy-aware policy engine with structured approval metadata
- Provider router for four AI model routes (fast, deep, code, compact)
- Primitive manifest catalog with capability tags, risk tiers, side effects, and evidence adapters
- Memory compaction and promotion service
- Task run lifecycle with checkpoints, traces, heartbeats, and replayable local state
- Behavior verifier for loop detection and evidence quality checks
- Structured handoffs, notifications, sync jobs, artifacts, and session state
- Operator Q&A via `ask` with per-session chat log
- Textual TUI and plain terminal fallback
- HTML5 web console for remote control and audit
- Notion sync, Discord delivery, and Caido adapters

## Quick Start

```bash
export PRIMORDIAL_DATABASE_URL='postgresql://primordial:primordial@localhost:5432/primordial'
python3 cli.py show
python3 cli.py scope
python3 cli.py tick
python3 cli.py run-loop --cycles 3
python3 cli.py compact
python3 cli.py process-queues
python3 cli.py add-target target.example --profile hackerone --asset target.example --asset 203.0.113.10
python3 cli.py approve <task_id>
python3 cli.py ask "status and next step" --target target.example
python3 cli.py tui
python3 cli.py web --port 1337
python3 cli.py models warm --keep-alive 8h
```

If `textual` is not installed, the `tui` command falls back to a plain terminal dashboard.

## Postgres Storage

Primordial requires Postgres and `pgvector`; SQLite runtime storage is no longer supported and there is no fallback importer. Initialize a database before starting the runtime:

```bash
createuser --pwprompt primordial        # skip if the role already exists
createdb -O primordial primordial      # skip if the database already exists
export PRIMORDIAL_DATABASE_URL='postgresql://primordial:<password>@localhost:5432/primordial'
psql "$PRIMORDIAL_DATABASE_URL" -c 'CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;'
```

The runtime creates its schema on startup and fails fast if `CREATE EXTENSION vector` is unavailable. Runtime outputs still live under `runtime/`, but that directory is ignored and should not be committed.

For local development, the bundled bootstrap creates `.venv`, installs Python and frontend dependencies, starts a local Postgres cluster under `runtime/postgres`, enables pgvector, and writes `runtime/primordial.env`:

```bash
scripts/bootstrap-v1.sh
source runtime/primordial.env
```

When run from the repository root, `python3 cli.py ...` also loads `runtime/primordial.env` automatically if the shell has not already set `PRIMORDIAL_DATABASE_URL`.

Stop that local cluster with:

```bash
scripts/stop-bootstrap-postgres.sh
```

Use the non-mutating doctor command to check a prepared environment:

```bash
python3 cli.py doctor
python3 cli.py doctor --json
```

`doctor` verifies DB reachability, `pgvector`, schema version, runtime directory writability, and that no `runtime/` files are tracked. It does not create schema, run model inference, validate credentials, run benchmarks, or execute security tooling.

## Autonomy Modes

Autonomy is a staged capability, not a default:

1. `assisted` — Orchestrator plans work and keeps context compact. Risky phases remain approval-gated.
2. `supervised` — Recon and low-risk analysis run continuously inside deterministic policy bounds. Exploitation, chaining, and premium escalation stay gated.
3. `supervised_auto` — More phases run without constant operator input. Exploitative work still requires `PRIMORDIAL_ALLOW_EXPLOITATIVE_ACTIONS=1` plus a valid agent safety review or human approval.
4. `high_autonomy` — Reserved for after evidence quality, primitive safety, and recovery loops are proven stable.

Autonomy grows from the workflow engine and policy layer, not from a bigger prompt.

## AI Model Routes

Four configured routes; route work based on role, not habit:

| Route | Purpose | Typical model |
|---|---|---|
| `local_fast` | Hot-path orchestration, broad analysis | `gemma3:12b` (GPU) |
| `local_deep` | Harder reasoning, operator Q&A | `deepseek-r1:8b` (GPU) |
| `local_code` | PoC research, exploit adaptation | `qwen2.5-coder:7b` (GPU, cold) |
| `local_compact` | Memory compaction, verifier checks | `phi4-mini` (CPU) |

`remote_premium` is policy-disabled by default.

AI calls are reserved for bounded moments: operator questions, task workers, verifier reviews, compaction/reconciliation, and explicit model warmup. Durable storage is always the source of truth.

## PoC Safety Gate

For an exploitation task to run without human approval, **all** of the following must be true:

- `PRIMORDIAL_AUTONOMY_MODE` is `supervised_auto` or `high_autonomy`
- `PRIMORDIAL_ALLOW_EXPLOITATIVE_ACTIONS=1` is set
- Task carries an `agent_safety_approval` from the behavior verifier
- Scope, evidence linkage, non-DoS classification, request limits, and timeout limits are explicit in that approval

Exploit research collects public examples only. PoC execution is never a default behavior.

## Local Model Setup

```bash
mkdir -p /home/bitloop/Desktop/PRIMORDIAL/AI_MODELS/ollama
export OLLAMA_MODELS=/home/bitloop/Desktop/PRIMORDIAL/AI_MODELS/ollama
export OLLAMA_MAX_LOADED_MODELS=4
export OLLAMA_NUM_PARALLEL=1
export OLLAMA_KEEP_ALIVE=8h
ollama serve
ollama pull gemma4:e4b
ollama pull phi4-reasoning
ollama pull qwen3-coder-next:q4_K_M
ollama pull deepseek-r1:8b
```

Or use the bundled setup script:

```bash
bash scripts/setup_ollama_models.sh
```

Then warm Primordial's configured routes:

```bash
python3 cli.py models warm --keep-alive 8h
ollama ps
```

## Running Tests

```bash
python3 -m unittest discover -s tests -t . -v     # full suite
python3 -m unittest tests.test_workflow -v
python3 -m unittest tests.test_policy -v
python3 -m unittest tests.test_runtime_integration -v
python3 -m unittest tests.test_web_console -v
```

Tests require Postgres with `pgvector`. Set `PRIMORDIAL_TEST_DATABASE_URL` to an existing test database, or let the test bootstrap start a temporary local cluster when `initdb`, `pg_ctl`, and `pgvector` are installed. Tests do not touch live runtime output.

For the full V1 hardening gate, use:

```bash
scripts/v1-gate.sh
```

The gate runs the Python suite, frontend build, live web smoke checks, and `doctor`. CI runs the same gate against a Postgres service with pgvector.

## Layout

```
primordial/core/
  domain/          enums, dataclasses, IDs, serialization
  events/          typed internal runtime event bus
  modules/         lazy module registration and lifecycle
  orchestration/   workflow engine, policy, verifier
  providers/       route selection and hot-path scheduling
  recovery/        crash journal and recovery helpers
  primitives/      manifest catalog and capability lookup
  storage/         Postgres schema and durable runtime store
  validation/      input and output validation helpers
  web/             HTML5 remote controller and audit console
  skills.py        skill surface registry
  credentials.py   secret storage and redaction
  findings_context.py  durable findings/guidance workspace

primordial/modes/security/
  methodology.py   phase/task blueprints
  execution.py     security-task execution and evidence write-back
  memory.py        memory compaction/promotion rules

primordial/adapters/   Notion, Discord, Caido adapters
primordial/app/        runtime assembly and dependency wiring
primordial/gui/        local Tk GUI launcher
primordial/ui/         Textual TUI shell and terminal fallback

manifests/         primitive manifests (capability tags, risk tiers, schemas)
tests/             test suite (CI-ready)
docs/              contributor documentation
```

The intent is `core` stays reusable, `modes/security` preserves product behavior, `adapters` isolate outside systems, `app` wires the runtime, and UI layers stay thin.

## Contributor Docs

- [docs/HOW_PRIMORDIAL_WORKS.md](docs/HOW_PRIMORDIAL_WORKS.md)
- [docs/FLOOR_PLAN.md](docs/FLOOR_PLAN.md)
- [docs/HUMAN_CHANGE_GUIDE.md](docs/HUMAN_CHANGE_GUIDE.md)

## Hard Boundaries

- **DDoS is always forbidden.** The system will never propose, automate, or assist with DDoS in any form.
- Only targets explicitly authorized within scope are supported.
- If scope is ambiguous, the system stops and requires operator clarification before proceeding.
