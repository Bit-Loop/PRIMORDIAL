# Quick Complexity Notes
Generated: 2026-05-15

## Size (core, excluding .venv / vendor)

| File | LOC | Decisions | Loops | Tier |
|---|---:|---:|---:|---|
| primordial/modes/security/execution.py | 4,289 | 726 | 104 | critical |
| primordial/app/runtime.py | 3,891 | 633 | 59 | critical |
| primordial/core/orchestration/workflow.py | 1,969 | 322 | 35 | critical |
| primordial/core/storage/runtime.py | 2,023 | 138 | 9 | medium |
| primordial/core/web/app.py | 1,574 | 502 | 24 | critical |
| primordial/core/providers/model_eval.py | 1,158 | 162 | 24 | high |
| primordial/core/orchestration/policy.py | 379 | 73 | 1 | medium |
| primordial/modes/security/memory.py | 214 | 37 | 7 | medium |
| **Total tracked** | **~43,000** | **3,410** | **346** | |

---

## Big-O Per Subsystem

| Subsystem | Complexity | Notes |
|---|---|---|
| Policy evaluation | **O(1)** | 7 sequential constant-time gates — fastest path |
| Task execution dispatch | **O(1)** | `getattr` dynamic dispatch to handler |
| Recon scan | **O(p × h)** | p = probe plans, h = HTML response size |
| Workflow planning tick | **O(T × n)** | T = targets, n = evidence per target |
| Memory freshness decay | **O(m)** | Linear scan, no batching |
| Generation supersession | **O(e)** | Full episodic scan per call |
| **Memory compaction dedup** | **O(m²)** | Loop calls `_supersede_conflicts()` → full SELECT per iteration; 500 entries = 250k DB round-trips worst case |

---

## Top Algorithmic Risk: Memory Compaction

`memory.py:202–206` — `_supersede_conflicts()` is called inside a loop over newly created entries. Each call issues a `list_memory_entries()` query. With 500 new entries and 500 existing, that's 500 separate SELECTs. Fix: batch UPDATE with a single query keyed on title hash or ID.

---

## Cyclomatic Complexity Hotspots

| Function | File | Branches | Notes |
|---|---|---:|---|
| `_evaluate_target_methodology_state()` | workflow.py:411 | 15+ | Multi-phase state machine, evidence filtering |
| `_methodology_candidate_actions()` | workflow.py:553 | 12+ | Per-primitive branching |
| `_handle_recon_scan()` | execution.py:277 | ~40 | Nested probe loops + HTML parsing |
| `PrimitiveExecutor.execute()` | execution.py:157 | 15+ | Dynamic dispatch to 15+ handlers |
| web dispatch | web/app.py | 157 gates | Long if/else routing chain |

execution.py overall: **726 branch statements**, loop nesting depth 3.

---

## God Objects

- `primordial/app/runtime.py` — 161 methods, 3,891 LOC. Everything touches this.
- `primordial/core/storage/runtime.py` — 132 methods, 2,023 LOC. All DB access goes through here.

Both are acknowledged in CLAUDE.md. Don't add more to either.

---

## Database Query Patterns

| Pattern | Risk | Location |
|---|---|---|
| `SELECT WHERE target_id = ?` | Safe — FK indexed | runtime.py:1382, 1414 |
| `SELECT * LIMIT N ORDER BY created_at` | Safe — bounded | runtime.py:388, 1141 |
| `SELECT FOR UPDATE SKIP LOCKED` | Safe — pessimistic lock | runtime.py:960–976 |
| `list_tasks()` + `list_task_runs()` separately | Moderate N+1 | runtime.py:1142–1145 |
| Supersede loop in compaction | **HIGH — O(m²) queries** | memory.py:202–206 |

No JOINs. In-memory joins via dict comprehension throughout. No index on generation fields — generation filtering does full table scans.

---

## Concurrency Model

```
Main Thread (single-threaded orchestrator)
├── RLock: _metrics_lock (2s TTL cache)
├── Web Console Thread (ThreadingHTTPServer)
│   ├── Lock: _tick_lock — serializes ticks (primary bottleneck)
│   └── RLock: _lock, _actions_lock
└── Background Tick Thread (continuous mode only)

Parallelism: ThreadPoolExecutor(max_workers=18) — HTTP probes only
```

**Known races:**
- Memory compaction reads evidence then writes entries without a transaction — concurrent tick creates a corruption window.
- Metrics cache TTL (2s) is checked but not enforced atomically.

---

## Structural Assessment

**Architecture: good.** Tick-based determinism, policy gating, evidence provenance, generation-aware filtering — all correct choices. Most AI-adjacent systems skip these invariants entirely.

**Implementation discipline: uneven.** The layer map is correct on paper. The actual weight is concentrated in two god objects. The design says "edit lowest first" and then `runtime.py` has 191 methods.

**Worst risks (priority order):**
1. O(m²) compaction dedup — will lock the system at scale
2. execution.py size — 4,289 LOC, 726 branches, depth-3 loops; one bad edit cascades
3. No transaction around compaction write — race window with concurrent ticks
4. N+1 queries (tasks + runs fetched separately) — one JOIN fixes it
5. No generation-field index — every generation filter does a full table scan

**The system is I/O-bound at the DB, not CPU-bound.** Fixing compaction dedup + adding generation indexes would have the highest real-world impact.
