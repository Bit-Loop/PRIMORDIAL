# Primordial

Primordial is a local-first control plane for AI-assisted authorized security workflows. It is being built from the PRD and current-context documents in this directory, with autonomy treated as a staged capability behind deterministic policy, durable workflow state, evidence lineage, and operator controls.

## Current Implementation

This first cut is a real application scaffold, not a mockup:

- Python package and CLI entrypoint
- durable local bootstrap store using `sqlite3` for development
- control-plane domain models for targets, tasks, evidence, notes, interests, findings, memory, policy, and traces
- methodology-aware task planner
- autonomy-aware policy engine
- provider router for hot-path vs cold-path model selection
- primitive manifest catalog
- memory compaction and promotion service
- task run lifecycle with checkpoints, traces, heartbeats, and replayable local state
- structured handoffs, notifications, sync jobs, artifacts, and session state
- Textual TUI entrypoint with a plain terminal fallback
- local adapter implementations for Notion sync, Discord delivery, and premium-review routing semantics

The long-term canonical live store remains `PostgreSQL + pgvector`, but the bootstrap implementation uses SQLite so the system can run immediately without external services. That keeps the architecture direction from the docs while still giving you a working baseline to extend.

## Core Principles Embedded In Code

- No risky action without policy evaluation
- No durable memory without evidence and metadata
- No freeform always-on agent loop
- No full-history context by default
- Autonomy must be event-driven, inspectable, and reversible
- PoC execution requires scope binding, non-DoS classification, bounded runtime limits, and approval

## Autonomy Roadmap

Autonomy is treated as core, but not as unrestricted execution:

1. `assisted`
   - Orchestrator plans work and keeps context compact.
   - Risky phases remain approval-gated.
2. `supervised`
   - Recon and low-risk analysis can run continuously inside deterministic policy bounds.
   - Exploitation, chaining, and premium escalation stay gated.
3. `supervised_auto`
   - More phases run without constant operator input.
   - Exploitative work still requires explicit `PRIMORDIAL_ALLOW_EXPLOITATIVE_ACTIONS=1` plus a valid agent safety review or human approval.
4. `high-autonomy`
   - Reserved for later after evidence quality, primitive safety, and recovery loops are proven.

The present codebase is designed so autonomy grows from the workflow engine and policy layer, not from a bigger prompt.

## AI Runtime Policy

Primordial does not run an always-on chat agent. AI calls are reserved for bounded moments: operator questions, task workers, verifier reviews, compaction/reconciliation, and explicit model warmup. This avoids wasting context and keeps durable storage as the source of truth.

Operator AI chat is stored in the runtime database and mirrored as per-message JSON files under `chat_log/YYYY-MM-DD/` for later analysis.

The intended model split is:

- `local_fast` on GPU for quick orchestration and broad analysis.
- `local_code_cold` on CPU for mission-critical code/exploit research, exploit synthesis, and high-consequence adaptation work.
- `local_deep` for harder reasoning and operator questions that cannot be answered deterministically from state.
- `local_compact` on CPU for notes, compaction, verifier checks, and slower background review.

Low CPU usage is expected when there are no compaction, verifier, or cold-review jobs. A high CPU burn rate should come from an explicit scheduled review or model invocation, not an idle loop.

## PoC Safety Gate

Exploit research is allowed to collect public examples, but it does not execute them. If non-DoS PoC candidates are found, Primordial writes evidence, creates an interest, and queues a high-priority Discord notification.

Automatic PoC execution is not a default behavior. For an exploitation task to pass without human approval, all of the following must be true:

- `PRIMORDIAL_AUTONOMY_MODE` is `supervised_auto` or `high_autonomy`.
- `PRIMORDIAL_ALLOW_EXPLOITATIVE_ACTIONS=1` is set.
- The task includes an `agent_safety_approval` from `behavior_verifier`, `policy_verifier`, or `exploit_safety_reviewer`.
- Scope, evidence linkage, non-DoS classification, request limits, and timeout limits are explicit in that approval.
- HackerOne targets additionally require target metadata allowing agent PoC execution because program rules differ.

## Quick Start

From this directory:

```bash
python3 -m primordial.cli show
python3 -m primordial.cli scope
python3 -m primordial.cli tick
python3 -m primordial.cli run-loop --cycles 3
python3 -m primordial.cli compact
python3 -m primordial.cli process-queues
python3 -m primordial.cli add-target pirate.htb --profile hack_the_box --asset pirate.htb --asset 10.129.47.117
python3 -m primordial.cli approve <task_id>
python3 -m primordial.cli tui
python3 -m primordial.cli web --port 1337
```

If `textual` is not installed, the `tui` command falls back to a plain terminal dashboard instead of failing.

## Layout

- `primordial/core/`: reusable control-plane code
  - `domain/`: enums, dataclasses, IDs, serialization helpers
  - `events/`: typed internal runtime event bus
  - `modules/`: lazy module registration and lifecycle
  - `orchestration/`: workflow engine, policy, verifier
  - `providers/`: route selection and hot-path scheduling
  - `recovery/`: crash journal and recovery helpers
  - `primitives/`: manifest catalog and capability lookup
  - `storage/`: schema and durable runtime store
  - `web/`: HTML5 remote controller and audit console
- `primordial/modes/security/`: the current authorized security-testing mode
  - `methodology.py`: phase/task blueprints
  - `execution.py`: security-task execution and evidence write-back
  - `memory.py`: security-mode memory compaction/promotion rules
- `primordial/adapters/`: Notion and Discord service adapters
- `primordial/app/`: runtime assembly and dependency wiring
- `primordial/ui/`: Textual UI shell and terminal fallback
- `primordial/config.py` and `primordial/runtime.py`: thin compatibility facades
- `manifests/`: sample primitive manifests
- `scopes/`: sample scope input

The intent is:

- `core` is the reusable control plane
- `modes/security` preserves the current product behavior
- `adapters` isolate outside systems
- `app` wires the whole runtime together
- `ui` stays operator-facing

Contributor docs:

- `docs/HOW_PRIMORDIAL_WORKS.md`
- `docs/FLOOR_PLAN.md`
- `docs/HUMAN_CHANGE_GUIDE.md`

## Local Model Setup

Primordial now expects local Ollama models to live in:

```bash
/home/bitloop/Desktop/PRIMORDIAL/AI_MODELS/ollama
```

Manual setup:

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
bash /home/bitloop/Desktop/PRIMORDIAL/scripts/setup_ollama_models.sh
```

After the server is running, warm Primordial's configured routes:

```bash
python3 /home/bitloop/Desktop/PRIMORDIAL/cli.py models warm --keep-alive 8h
ollama ps
```

Ollama may still evict models if the requested set does not fit available VRAM/RAM. Primordial treats warmup as an operational check and records failures instead of crashing the runtime.

## V1 Direction

The near-term target is a narrow but real operator platform:

- scope import
- task planning
- policy gating
- durable notes and evidence
- context compaction
- per-target workflow visibility
- selective escalation routing

That is the base needed before deeper autonomy, chaining, or broad tool onboarding can become trustworthy.

## Current Integration Boundary

The repository now implements the workflow, state, routing, and write-back paths for:

- local-fast, local-deep, local-compact, and remote-premium routes
- Notion sync jobs and target-subtree page generation
- Discord notification queuing, live webhook delivery, and delivery records
- premium review packaging and teach-back write-back

Notion and Discord adapters now use locally stored credentials when configured. Remote premium/Anthropic execution remains policy-disabled by default and is not used until explicitly enabled later.
