---
origin: source_markdown
migration_ref: catalog/policies/markdown_migrations.yaml
ingest_allowed: false
operational_retrieval_allowed: false
---

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
- Provider router for five AI model routes (fast, deep, code, compact, agent-chat)
- Primitive manifest catalog with capability tags, risk tiers, side effects, and evidence adapters
- YAML capability catalog: intents, playbooks, heuristics, and semantic capability semantics
- RAG pipeline: document ingestion (Docling), MITRE ATT\&CK STIX parsing, pgvector semantic search, and policy-gated task hints
- Memory compaction and promotion service
- Task run lifecycle with checkpoints, traces, heartbeats, and replayable local state
- Behavior verifier for loop detection and evidence quality checks
- Structured handoffs, notifications, sync jobs, artifacts, and session state
- Operator Q\&A via `ask` with per-session chat log
- Agent Chat API: standalone HTTP wrapper for Claude Code and Codex CLIs with OpenAI-compatible interface
- Textual TUI and plain terminal fallback
- HTML5 web console (React + Vite) for remote control and audit
- Notion sync, Discord delivery, and Caido proxy adapters

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

Primordial requires Postgres and `pgvector`. Initialize a database before starting:

```bash
createuser --pwprompt primordial        # skip if the role already exists
createdb -O primordial primordial       # skip if the database already exists
export PRIMORDIAL_DATABASE_URL='postgresql://primordial:<password>@localhost:5432/primordial'
psql "$PRIMORDIAL_DATABASE_URL" -c 'CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;'
```

The runtime creates its schema on startup and fails fast if `CREATE EXTENSION vector` is unavailable. Runtime outputs live under `runtime/` and are gitignored.

For local development, the bootstrap script creates `.venv`, installs dependencies, starts a local Postgres cluster under `runtime/postgres`, enables pgvector, and writes `runtime/primordial.env`:

```bash
scripts/bootstrap-v1.sh
source runtime/primordial.env
```

`python3 cli.py ...` from the repo root also loads `runtime/primordial.env` automatically if `PRIMORDIAL_DATABASE_URL` is not already set.

Stop the local cluster:

```bash
scripts/stop-bootstrap-postgres.sh
```

Run the non-mutating health check:

```bash
python3 cli.py doctor
python3 cli.py doctor --json
```

`doctor` verifies DB reachability, `pgvector`, schema version, runtime directory writability, and that no `runtime/` files are tracked. It does not create schema, run inference, validate credentials, or execute security tooling.

## CLI Reference

```
tick                  Run one orchestration tick
repair                Recover stale execution state without running tools
run-loop              Run repeated ticks (--cycles N, --max-executions N)
show                  Render dashboard snapshot to stdout
scope                 Show current scope, targets, assets (--json)
compact               Run one memory compaction cycle
process-queues        Process Notion and Discord delivery queues
tui                   Launch Textual UI or terminal fallback
gui / web             Launch HTML5 web console (--host, --port)
stop-server           Gracefully stop web console (--kill for SIGKILL)
doctor                Check Postgres, pgvector, schema, runtime (--json)

add-target            Add or update a target (--profile, --display-name, --asset)
remove-target         Remove a target and linked records (--profile)
import-scope          Import JSON or line-based scope file (--profile)
start-session         Start new methodology session (--methodology, --title)
approve               Approve pending tasks (--all-safe, --tick, --limit)
deny                  Deny a pending task

ask                   Bounded operator AI Q&A (--target)

models warm           Preload configured local models into Ollama (--keep-alive)
models status         Show installed models and role mappings (--json)
models set-role       Assign a model to a runtime role
models evaluate       Benchmark models on safe code and synthetic tasks
models tune-lmstudio  Tune LM Studio load settings (--model, --context)

credentials status    Show redacted credential status (--json)
credentials set-notion          Set Notion integration
credentials set-discord         Set Discord webhook
credentials set-known / set-lab Set known/lab credentials
credentials set-caido           Set Caido GraphQL credentials
credentials clear               Clear credentials by service name

skills list           List loaded skill summaries (--json, --include-body)

findings-context show     Show per-target findings workspace paths
findings-context sync     Regenerate Notion export mirrors

rag ingest            Import a document for a target (--target, --corpus-type)
rag preprocess-attck  Parse MITRE ATT&CK STIX JSON into structured indexes
rag search            Semantic search over ingested documents (--limit)
rag cve-search        Search CVE advisory and exploit-note chunks
rag hints             Show policy-gated direct task hints from RAG

caido status          Show Caido config and optional health check (--check-health)
```

## Autonomy Modes

Autonomy is a staged capability, not a default:

1. `assisted` — Orchestrator plans work and keeps context compact. Risky phases remain approval-gated.
2. `supervised` — Recon and low-risk analysis run continuously inside deterministic policy bounds. Exploitation, chaining, and premium escalation stay gated.
3. `supervised_auto` — More phases run without constant operator input. Exploitative work still requires `PRIMORDIAL_ALLOW_EXPLOITATIVE_ACTIONS=1` plus a valid agent safety review or human approval.
4. `high_autonomy` — Reserved for after evidence quality, primitive safety, and recovery loops are proven stable.

Autonomy grows from the workflow engine and policy layer, not from a bigger prompt.

## AI Model Routes

Five configured routes; route work based on role, not habit:

| Route | Purpose | Typical model |
|---|---|---|
| `local_fast` | Hot-path orchestration, broad analysis | `gemma3:12b` (GPU) |
| `local_deep` | Harder reasoning, operator Q&A | `deepseek-r1:8b` (GPU) |
| `local_code` | PoC research, exploit adaptation | `qwen2.5-coder:7b` (GPU, cold) |
| `local_compact` | Memory compaction, verifier checks | `phi4-mini` (CPU) |
| `agent_chat` | Bounded AI review via Agent Chat API | Claude / Codex |

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

Then warm configured routes:

```bash
python3 cli.py models warm --keep-alive 8h
ollama ps
```

## Agent Chat API

A standalone HTTP service (`agent_chat_api/`) that wraps Claude Code and Codex CLIs for use as Primordial's `agent_chat` provider route.

Endpoints:
- `GET /health` — Health check
- `POST /api/chat` — Simple chat
- `POST /v1/chat/completions` — OpenAI-compatible shape with streaming (SSE)

Features: persistent conversations via `conversation_id`, provider fallback (Codex → Claude), rate limiting, audit logging, read-only sandbox by default. A systemd user unit template is included at `agent_chat_api/systemd/`.

Key env vars:
```bash
PRIMORDIAL_AGENT_CHAT_BASE_URL=http://127.0.0.1:8787
PRIMORDIAL_AGENT_CHAT_API_KEY=<token>
PRIMORDIAL_AGENT_CHAT_PROVIDER=claude     # or codex
PRIMORDIAL_AGENT_CHAT_MODEL=<model>
```

## RAG Pipeline

Primordial includes a document ingestion and semantic search pipeline backed by `pgvector`.

```bash
# Ingest a document for a target
python3 cli.py rag ingest /path/to/doc.pdf --target target.example --corpus-type advisory

# Parse MITRE ATT&CK STIX bundles into structured indexes
python3 cli.py rag preprocess-attck --source-dir docs/RAG_SRC --out-dir runtime/attck

# Semantic search
python3 cli.py rag search "SMB relay attack" --target target.example --limit 10

# CVE and exploit note search
python3 cli.py rag cve-search "EternalBlue" --target target.example

# Policy-gated task hints derived from RAG
python3 cli.py rag hints "domain controller" --target target.example
```

Source materials go in `docs/RAG_SRC/`. Supported types include OWASP guides, pentest standards (PTES, NIST SP 800-115), MITRE ATT\&CK STIX JSON, CVE advisories, and operator-supplied references.

## Primitive Manifests

Each security primitive is declared in `manifests/<name>.json` with capability tags, risk tier, side effects, input/output schema, timeout, and evidence adapter. Current primitives:

`tcp-service-discovery` · `dns-enumeration` · `http-probe` · `content-discovery` · `credentialed-access-check` · `ad-enumeration` · `kerberos-user-discovery` · `kerberos-attack-check` · `searchsploit-research` · `poc-applicability-validation` · `finding-verification` · `hypothesis-analysis` · `behavior-review` · `chain-review` · `claude-review` · `caido-search` · `notion-sync` · `discord-alert` · `memory-compactor`

Agents reason about capability classes, not raw shell commands.

## Capability Catalog

`catalog/` holds YAML-based operator intents, playbooks, and heuristics that feed task generation and routing:

- `intents/` — Operator intent profiles: `recon_only`, `web_triage`, `credential_validation`, `exploit_research_allowed`, `htb_lab`, `ad_lab`
- `playbooks/` — Structured workflow sequences (e.g., `htb_windows_flag_collection`, `ad_enumeration`)
- `heuristics/` — Scoring heuristics for web discovery, service identification, exploit research
- `capabilities/` — Semantic tag definitions and risk classification

## Environment Variables

**Required:**
```bash
PRIMORDIAL_DATABASE_URL                 # Postgres connection string
```

**Runtime directories** (all default under `runtime/`):
```bash
PRIMORDIAL_RUNTIME_DIR
PRIMORDIAL_ARTIFACTS_DIR
PRIMORDIAL_CHAT_LOGS_DIR
PRIMORDIAL_CHECKPOINTS_DIR
PRIMORDIAL_CRASH_JOURNAL_PATH
PRIMORDIAL_FINDINGS_DIR
PRIMORDIAL_NOTION_EXPORTS_DIR
PRIMORDIAL_EXPORTS_DIR
PRIMORDIAL_MANIFESTS_DIR
PRIMORDIAL_CATALOG_DIR
PRIMORDIAL_SKILLS_DIR
PRIMORDIAL_SECRETS_DIR
PRIMORDIAL_CREDENTIALS_PATH
```

**Autonomy and policy:**
```bash
PRIMORDIAL_AUTONOMY_MODE                # assisted | supervised | supervised_auto | high_autonomy
PRIMORDIAL_ALLOW_EXPLOITATIVE_ACTIONS   # 1 to enable PoC execution paths
PRIMORDIAL_ALLOW_PASSWORD_ARG_TOOLS     # 1 for WinRM password-arg tools
PRIMORDIAL_ALLOW_REMOTE_CAIDO          # 1 to enable remote Caido integration
PRIMORDIAL_ALLOW_DESTRUCTIVE_TARGET_DELETE
PRIMORDIAL_MAX_EVIDENCE_ITEMS           # default 50
PRIMORDIAL_CONTENT_DISCOVERY_WORDLIST   # custom wordlist path
```

**AI providers:**
```bash
OLLAMA_BASE_URL                         # default http://127.0.0.1:11434
LMSTUDIO_BASE_URL                       # default http://127.0.0.1:1234
LMSTUDIO_API_TOKEN
NOTION_API_BASE_URL                     # default https://api.notion.com/v1
```

**Agent Chat API:**
```bash
PRIMORDIAL_AGENT_CHAT_BASE_URL          # default http://127.0.0.1:8787
PRIMORDIAL_AGENT_CHAT_API_KEY
PRIMORDIAL_AGENT_CHAT_MODEL
PRIMORDIAL_AGENT_CHAT_PROVIDER          # claude | codex
PRIMORDIAL_AGENT_CHAT_CODEX_SANDBOX     # default read-only
PRIMORDIAL_AGENT_CHAT_CLAUDE_PERMISSION_MODE
PRIMORDIAL_AGENT_CHAT_CWD
```

**Local Postgres bootstrap** (used by `scripts/bootstrap-v1.sh`):
```bash
PRIMORDIAL_BOOTSTRAP_PG_ROOT
PRIMORDIAL_BOOTSTRAP_PG_PORT            # default 55432
PRIMORDIAL_BOOTSTRAP_PG_USER            # default primordial
PRIMORDIAL_BOOTSTRAP_PG_DB             # default primordial
```

## Running Tests

```bash
python3 -m unittest discover -s tests -t . -v     # full suite
python3 -m unittest tests.test_workflow -v
python3 -m unittest tests.test_policy -v
python3 -m unittest tests.test_runtime_integration -v
python3 -m unittest tests.test_web_console -v
python3 -m unittest tests.test_rag -v
python3 -m unittest tests.test_agent_chat_integration -v
```

Tests require Postgres with `pgvector`. Set `PRIMORDIAL_TEST_DATABASE_URL` to an existing test database, or let the test bootstrap start a temporary local cluster when `initdb`, `pg_ctl`, and `pgvector` are installed. Tests do not touch live runtime output.

For the full V1 hardening gate:

```bash
scripts/v1-gate.sh
```

The gate runs the Python suite, frontend build, live web smoke checks, and `doctor`. CI runs the same gate against a Postgres service with pgvector.

## Complexity Profile

~43,000 LOC across 94 Python files. Project difficulty: high. Most orchestration files are large state machines with tightly coupled policy, I/O, and risk logic.

| Subsystem | Complexity | Notes |
|---|---|---|
| Policy evaluation | O(1) | 7 constant-time gates — fastest path |
| Task execution dispatch | O(1) | `getattr` dynamic dispatch |
| Recon scan | O(p × h) | p = probe plans, h = HTML response size |
| Workflow planning tick | O(T × n) | T = targets, n = evidence per target |
| Memory compaction dedup | **O(m²)** | Known hotspot — `_supersede_conflicts()` in a loop |

Known structural risks:
- `primordial/app/runtime.py` and `primordial/core/storage/runtime.py` are god objects — do not add more logic to either.
- `primordial/modes/security/execution.py` has 726 branch statements and depth-3 nesting.
- Memory compaction issues O(m²) DB queries worst case — highest-priority fix.
- No index on generation fields — generation filtering is a full table scan.
- No transaction wrapper around compaction writes — race window with concurrent ticks.

See `quick-complexity-notes.md` for the full per-file analysis.

## Layout

```
primordial/core/
  domain/          enums, dataclasses, IDs, serialization
  events/          typed internal runtime event bus
  modules/         lazy module registration and lifecycle
  orchestration/   workflow engine, policy, verifier
  providers/       route selection, hot-path scheduling, LM Studio, Ollama, Agent Chat
  recovery/        crash journal and recovery helpers
  primitives/      manifest catalog and capability lookup
  storage/         Postgres schema and durable runtime store
  validation/      input and output validation helpers
  web/             HTML5 remote controller and audit console
  rag/             document ingestion, embeddings, ATT&CK parsing, semantic search
  evidence/        evidence surface definitions
  autonomy/        failure analysis, safety, methodology proposals
  intent/          operator intent registry
  catalog/         YAML capability loader (intents, playbooks, heuristics)
  skills.py        skill surface registry
  credentials.py   secret storage and redaction
  findings_context.py  durable per-target findings/guidance workspace
  doctor.py        health check utility
  startup.py       preflight checks
  local_runtime.py env loading and local Postgres bootstrap

primordial/modes/security/
  methodology.py   phase/task blueprints
  execution.py     security-task execution and evidence write-back
  memory.py        memory compaction/promotion rules

primordial/adapters/   Notion, Discord, Caido adapters
primordial/app/        runtime assembly and dependency wiring
primordial/gui/        local Tk GUI launcher
primordial/ui/         Textual TUI shell and terminal fallback

agent_chat_api/        standalone HTTP wrapper for Claude Code / Codex CLIs
manifests/             primitive manifests (capability tags, risk tiers, schemas)
catalog/               capability catalog (intents, playbooks, heuristics)
gui/                   React JSX source (dashboard, chat, caido, map, pair, interests)
docs/                  contributor documentation and RAG source materials
tests/                 test suite (CI-ready, 23 test files)
scripts/               bootstrap, stop-postgres, v1-gate, model setup, GUI build
```

The intent is `core` stays reusable, `modes/security` preserves product behavior, `adapters` isolate outside systems, `app` wires the runtime, and UI layers stay thin.

## Contributor Docs

- [docs/HOW_PRIMORDIAL_WORKS.md](docs/HOW_PRIMORDIAL_WORKS.md)
- [docs/FLOOR_PLAN.md](docs/FLOOR_PLAN.md)
- [docs/HUMAN_CHANGE_GUIDE.md](docs/HUMAN_CHANGE_GUIDE.md)
- [docs/MODEL_SELECTION_NOTES.md](docs/MODEL_SELECTION_NOTES.md)

## Hard Boundaries

- **DDoS is always forbidden.** The system will never propose, automate, or assist with DDoS in any form.
- Only targets explicitly authorized within scope are supported.
- If scope is ambiguous, the system stops and requires operator clarification before proceeding.
