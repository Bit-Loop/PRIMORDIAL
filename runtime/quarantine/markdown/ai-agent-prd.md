---
origin: source_markdown
migration_ref: catalog/policies/markdown_migrations.yaml
ingest_allowed: false
operational_retrieval_allowed: false
---

# PRD - AI Agent Orchestration TUI for Authorized Security Testing

Last updated: 2026-05-04
Status: Draft v0

## Current Tracking Note

The planning baseline now assumes the host can keep multiple models resident in RAM. The product should therefore distinguish between:

- hot-path models used for continuous orchestration and note compaction
- cold-path models used for slow but deeper periodic review, reconciliation, and memory rebuilding

The planning baseline also assumes a very fast PCIe 5.0 NVMe device. This makes append-heavy logs, large artifact retention, frequent checkpoints, vector index maintenance, and memory snapshot/rebuild jobs much more practical than on typical consumer disks.

## 1. Overview

Build a local-first CLI/TUI application that orchestrates AI-assisted, methodology-driven security testing workflows for authorized environments such as HackerOne bug bounty scopes and Hack The Box labs. The system must manage tools, notes, context, evidence, and long-running execution without relying on a single ever-growing prompt session.

## 2. Problem Statement

Existing agentic security workflows often fail in one or more of these ways:

- Too much raw tool surface is exposed to the LLM
- Context grows until quality collapses
- Notes are unstructured and hard to query
- Long-running sessions drift, stall, or loop
- Scope and policy boundaries are not enforced strongly enough
- Local-only setups struggle to match stronger cloud models on harder reasoning tasks

The product should address these issues through structured orchestration, strict state management, and pluggable model backends.

## 3. Vision

Create a terminal-native operator cockpit for long-running, AI-assisted authorized security work:

- The operator provides a scope and methodology
- The system runs continuously and safely within policy
- AI plans tasks, manages context, and maintains notes
- Evidence and actions remain inspectable and reproducible
- Stronger providers such as Claude agents can be invoked selectively when useful

## 4. Target Users

- Individual bug bounty hunters
- Independent pentesters
- Internal security engineers
- CTF / Hack The Box operators

## 5. Primary Use Cases

- Import a HackerOne scope list or scope file and normalize it into internal targets
- Run continuous methodology-driven auditing against in-scope assets
- Track “interests” such as suspicious endpoints, auth artifacts, parameters, privilege boundaries, or behaviors worth revisiting
- Maintain AI-generated notes that remain compact, queryable, and evidence-linked
- Sync operator-facing notes into Notion with per-target organization
- Use Caido-integrated capabilities for traffic search, replay, findings, and related workflows
- Escalate select tasks to Claude agents or other premium providers when local models are insufficient
- Identify and verify multi-step vulnerability chains from otherwise isolated observations
- Send high-signal notifications to Discord when important events occur

## 6. Non-Goals for Early Versions

- Fully autonomous unrestricted offensive action
- Replacing Caido as the HTTP testing source of truth
- Running every possible script directly through the LLM
- Relying on one giant conversational context for multi-day operation
- Assuming all local models can handle deep business-logic reasoning at top-tier quality

## 7. Core Product Requirements

### 7.1 Scope Management

- Accept HackerOne scope files/lists and normalize asset definitions
- Preserve per-asset metadata where available
- Support separate profiles for HackerOne and Hack The Box
- Enforce in-scope/out-of-scope policy at execution time

### 7.2 Methodology Engine

- Present methodologies as selectable workflows in the TUI
- Allow phases, gates, retry policies, and branching rules
- Restrict the orchestrator to admissible next actions
- Allow humans to pause, resume, approve, deny, or reprioritize work
- Initial methodology phases under consideration:
  - recon
  - hypothesis / analysis
  - exploitation
  - chaining
  - verification of agent behavior

### 7.3 Agent Orchestration

- Support a primary orchestrator role
- Support bounded task workers
- Support provider abstraction for local models and Claude agents
- Enable task-level escalation to stronger providers
- Support specialist agents such as vulnerability chaining and agent-behavior verification

### 7.4 Context and Note Management

- AI must actively manage notes and context
- Store structured notes, not only freeform text
- Summarize, compact, dedupe, cluster, and relink notes over time
- Preserve evidence provenance
- Track confidence, freshness, and relevance
- Support a Notion sync/export layer for operator-facing note organization
- Organize notes per target/program in Notion using a folder-like page/subtree structure
- Keep local structured storage as the canonical source of truth rather than treating Notion as primary storage

### 7.5 Tool / Primitive Management

- Wrap tools and scripts as typed primitives
- Define input schema, output schema, side effects, timeout, and cost hints
- Limit what the LLM can see to approved primitives
- Support large script collections without overwhelming prompt space
- Support large heterogeneous external toolchains without requiring the model to reason directly about raw scripts or binary names
- Support manifest-driven onboarding for existing tools and scripts
- Support capability-based routing so agents choose classes of action rather than arbitrary executables
- Support output normalization and evidence extraction for noisy tool output
- Support per-tool risk tiers, sandbox profiles, secret requirements, install state, and health status
- Support grouping tools into bundles/profiles by workflow, target type, and methodology phase

### 7.6 Long-Running Reliability

- Designed to run continuously for days
- Use queues, leases, heartbeats, retries, and checkpoints
- Avoid persistent unbounded prompt sessions
- Persist all critical state to disk
- Recover cleanly after crashes or model/tool failures

## 8. Functional Components

### 8.1 TUI

Potential areas:

- Dashboard
- Scope browser
- Methodology menu
- Task queue view
- Interests view
- Notes/context view
- Findings/evidence view
- Model/provider view
- Logs/health view
- Notification/approval view

### 8.2 Data Model

Core entities likely include:

- Target
- Scope asset
- Methodology
- Phase
- Task
- Primitive
- Note
- Interest
- Evidence
- Finding
- Session
- Provider
- Policy rule
- Notification event
- External sync state

### 8.3 Model Providers

- Local GPU model for planning/reasoning
- Local CPU-friendly model for summarization and compaction
- Optional Claude-agent integration for hard tasks

### 8.4 Learning and Memory System

- The product must support continuous improvement without relying on unbounded prompt growth
- Separate model inference from memory accumulation
- Support at least three memory layers:
  - Working memory for the current task
  - Episodic memory for session/task outcomes
  - Semantic memory for durable facts and patterns
- AI-generated notes must be compacted continuously
- Facts should be promoted to durable memory only with evidence and confidence metadata
- Support periodic offline adaptation workflows such as dataset export, trace review, and optional adapter fine-tuning
- Do not require live online weight updates during active multi-day runs

### 8.5 Caido Integration

- Use Caido SDK/skills/client APIs where applicable
- Pull/search traffic and replay data
- Create or link findings/replays/notes
- Keep Caido as the operational testing backbone when working with web targets

## 9. Proposed Operating Model

- The orchestrator loads scope, policy, and methodology
- It generates bounded tasks from admissible workflow steps
- Workers execute tasks using typed primitives
- Results are converted into structured notes and evidence
- A compaction layer updates interests and keeps context small
- Higher-value unresolved tasks can be escalated to Claude agents

## 10. Initial Local Model Strategy (note we are using stronger and better models)

- Default topology:
  - One GPU-backed planner/reasoner
  - One CPU-friendly summarizer/compactor
- Candidate planner/reasoner families:
  - Qwen3 `8B` / `14B`
  - DeepSeek-R1 distilled `8B` / `14B`
  - Gemma 3 `12B`
  - Qwen2.5 `7B` / `14B`
- Candidate code/tooling specialists:
  - Qwen2.5-Coder `7B` / `14B`
  - Codestral `22B` only if latency is acceptable
- Candidate lightweight compaction/background models:
  - Phi-4-mini
  - Gemma 3 `4B`
  - Qwen small variants
- Provider routing should choose among:
  - local-fast
  - local-deep
  - local-code
  - remote-premium
- Current recommended baseline:
  - `local-fast`: `gemma3:12b`
  - `local-deep`: `deepseek-r1:8b`
  - `local-code`: `qwen2.5-coder:7b`
  - `local-compact`: `phi4-mini`
  - optional richer compact/summarize path: `gemma3:4b`

## 11. Runtime Matrix Draft

### 11.1 Agent Role Routing

- `Primary orchestrator`
  - Model: `gemma3:12b`
  - Responsibility:
    - select next admissible methodology step
    - decompose work into bounded tasks
    - rank interests and unresolved hypotheses
    - coordinate memory retrieval requests

- `Deep reasoning worker`
  - Model: `deepseek-r1:8b`
  - Responsibility:
    - evaluate subtle hypotheses
    - reason over competing evidence
    - inspect possible exploit chains

- `Code / primitive worker`
  - Model: `qwen2.5-coder:7b`
  - Responsibility:
    - generate helper code
    - adapt tooling wrappers
    - transform outputs into typed structures

- `Memory / notes worker`
  - Model: `phi4-mini`
  - Responsibility:
    - compact notes
    - dedupe and cluster
    - assign confidence/freshness labels
    - propose promotion/demotion actions

- `Optional richer summarizer`
  - Model: `gemma3:4b`
  - Responsibility:
    - higher-quality note synthesis when `phi4-mini` is too lossy

- `Vulnerability chaining worker`
  - Model: `deepseek-r1:8b` by default, with optional escalation
  - Responsibility:
    - combine evidence across tasks
    - propose exploit chains
    - identify prerequisites and blockers
    - generate bounded verification tasks for each claimed chain step

- `Agent-behavior verifier`
  - Model: `phi4-mini` for cheap checks, optional stronger reviewer for disputes
  - Responsibility:
    - detect loops, duplicate work, unsupported claims, prompt drift, and confidence inflation
    - score whether an agent action was justified by available evidence

### 11.2 Resource Expectations

- `gemma3:12b`
  - Expected VRAM: approximately `8-10GB` quantized in practical local serving setups

- `deepseek-r1:8b`
  - Expected VRAM: approximately `5-7GB` quantized

- `qwen2.5-coder:7b`
  - Expected VRAM: approximately `5-6GB` quantized

- `phi4-mini`
  - Expected RAM on CPU: approximately `4-8GB` practical range

- `gemma3:4b`
  - Expected RAM on CPU: approximately `6-10GB` practical range

These are planning estimates and must be validated against the chosen runtime, quantization, concurrency, and context settings.

- Additional CPU-resident reviewer tier made possible by `92GB` RAM: CPU potentially loadable with strong quantization and careful cache control, but expected to be very slow

### 11.3 Hot Path vs Cold Path  (important)

- `Hot path`
  - continuous orchestration
  - low-latency memory compaction
  - routine triage
  - bounded task execution
  - recommended models:
    - `gemma3:12b`
    - `deepseek-r1:8b`
    - `qwen2.5-coder:7b`
    - `phi4-mini`

- `Cold path`
  - periodic deep review
  - reconciliation of conflicting notes/interests
  - promotion review for important findings
  - nightly or scheduled semantic-memory rebuilds
  - recommended models:
    - `gemma3:27b`
    - `qwen2.5:32b`
    - `deepseek-r1:32b`

The vulnerability chaining worker should usually be warm but not continuously active; trigger it only when evidence density or relationship signals exceed thresholds.

### 11.4 Escalation Policy

- Escalate to Claude or GPT 5.5 when:
  - candidate findings hinge on subtle authorization or business-logic interpretation
  - local models disagree materially
  - evidence spans many artifacts and requires long-horizon synthesis
  - confidence is high but evidence quality is mixed
  - the system is preparing a final high-value finding summary
  - repeated bounded attempts fail to converge
  - a candidate exploit chain spans many conditional steps or ambiguous state transitions
  - exploit generation or refinement requires stronger reasoning than the local stack can reliably provide

- Keep work local when:
  - the task is repetitive or mechanical
  - the task is mostly compression, clustering, or tagging
  - the task is routine code/tool generation
  - the cost of escalation exceeds the expected value of stronger reasoning

### 11.4.0 Claude Augmentation Model

- Claude should be treated as a selective augmentation layer, not only a last-resort fallback
- Intended roles:
  - `stuck-task rescue`
    - when local workers fail to converge after bounded attempts
  - `exploit synthesis`
    - when stronger reasoning is needed to generate or refine exploit logic on top of existing tooling
  - `high-value review`
    - when local conclusions need stronger judgment
  - `teach-back`
    - when Claude-derived insights should be distilled into reusable memory, templates, or primitive improvements

- Operating principle:
  - local models handle breadth, low-cost triage, context maintenance, and routine execution
  - Claude handles sparse, high-value cognition where weaker models are the bottleneck

### 11.4.1 Claude Escalation Workflow

- `Trigger sources`
  - orchestrator
  - vulnerability chaining worker
  - behavior verifier
  - operator-initiated manual escalation

- `Escalation candidate requirements`
  - escalation reason
  - expected value
  - estimated cost tier
  - local-model disagreement or uncertainty signal
  - evidence references
  - desired output type

- `Rescue detection`
  - Workers should be marked as `stuck` using explicit signals rather than vague intuition
  - Primary signals:
    - repeated bounded attempts without confidence or evidence improvement
    - repeated proposal of the same next action
    - retry threshold exceeded
    - persistent local-model disagreement without convergence
    - inability to produce a valid next verification step
    - high uncertainty paired with weak evidence support
    - exploit-generation attempts that fail static/runtime validation repeatedly
    - oscillation between conflicting hypotheses
  - Secondary signals:
    - no materially new evidence over multiple iterations
    - repeated blocker across related tasks
    - verifier-detected loops, duplication, or unsupported-claim inflation
    - rising cost/latency without progress
  - Rescue should usually require either:
    - one severe signal
    - or multiple weaker signals combined into a threshold score

- `Policy and budget gates`
  - evaluate:
    - profile and target restrictions
    - approval requirements
    - daily/session/cloud budget
    - duplicate or near-duplicate recent escalations
    - whether cheaper local review already failed
  - deny escalation when the expected value is low or the question is still too under-specified

- `Escalation package construction`
  - build a compact structured package, not a raw transcript dump
  - include:
    - task summary
    - target and scope context
    - exact question/hypothesis
    - evidence summaries
    - minimal raw artifacts needed
    - current confidence and disagreement state
    - expected answer format

- `Escalation modes`
  - stuck-task rescue
  - exploit synthesis
  - reasoning review
  - exploit-chain review
  - final finding review
  - final writeup review
  - dispute resolution between local workers

- `Response contract`
  - Claude responses should be normalized into:
    - conclusion
    - confidence
    - reasoning summary
    - evidence gaps
    - next verification actions
    - uncertainty notes
    - exploit scaffold or refinement guidance when exploit synthesis is requested

- `Post-response handling`
  - Claude output must not become durable truth automatically
  - write back as:
    - reviewed note
    - finding candidate update
    - verification tasks
    - confidence change
  - high-impact conclusions still require bounded verification or human review

- `Teach-back handling`
  - When Claude materially improves an outcome, the system should distill the useful result into:
    - reusable notes/patterns
    - exploit-generation templates
    - primitive improvement ideas
    - retrieval hints for future similar tasks
  - This improves the local-first system over time without relying on live weight updates

- `Notification hooks`
  - generate operator notifications when Claude:
    - upgrades severity materially
    - changes confidence materially
    - rejects a previously favored chain
    - proposes a high-value next verification step

### 11.4.2 Notification Policy

- Use Discord as a high-signal notification channel
- Notification-worthy events include:
  - likely report-worthy finding candidates
  - major confidence or severity changes
  - Claude escalation results that materially alter direction
  - approval-required workflow gates
  - repeated workflow recovery failures
- Avoid notifications for:
  - routine recon noise
  - ordinary compaction activity
  - low-value repetitive triage updates
- Notifications should include:
  - target/program identifier
  - event type
  - concise summary
  - confidence/severity delta where relevant
  - link/reference back to the internal task/finding/note

### 11.5 Automatic Memory Compaction Policy

- Trigger compaction:
  - after every task completion
  - after ingesting large tool output
  - after scanner/replay batches
  - when working context reaches `60-70%` of budget
  - on a periodic timer during active runs

- Compaction levels:
  - `light`: summarize, dedupe, relink
  - `medium`: merge interests, compress task history, trim stale detail
  - `heavy`: rebuild semantic memory summaries and archive low-value traces

### 11.6 Continuous Learning Policy

- v1 learning should be memory-centric, not prompt-centric
- The system improves by:
  - accumulating structured evidence
  - refining notes over time
  - tracking successful and failed methodologies
  - improving retrieval and ranking
- Optional later phases may support offline adapter tuning or supervised fine-tuning from approved traces
- Active multi-day runs should not depend on live weight updates

### 11.7 Efficiency Guardrails

- Specialist agents must be event-driven, not constantly active
- Chaining work should require threshold signals such as:
  - repeated related interests
  - verified prerequisite artifacts
  - unresolved high-value hypotheses
- Agent-behavior verification should run cheaply and automatically on:
  - task completion
  - repeated retries
  - high-confidence claims
  - long-running task branches
- The system should prefer cheap local verification before premium-model escalation

### 11.8 Event-Driven Coordination Plan

- The orchestrator is the only always-on cognitive controller
- All specialist agents should be activated by explicit events and thresholds
- Example event sources:
  - new scope import
  - target state change
  - completed task
  - failed task
  - evidence ingestion
  - anomaly detection
  - timer tick
  - operator action

- Agent activation rules:
  - `Recon worker`
    - on new target, stale target, new auth artifact, or recon phase entry
  - `Critical thinking worker`
    - on evidence accumulation threshold or anomaly clustering
  - `Exploitation worker`
    - on prioritized verified hypothesis with prerequisites present
  - `Vulnerability chaining worker`
    - on related verified interests or partial exploit-path signals
  - `Agent-behavior verifier`
    - on high-confidence claim, repeated retries, duplicate patterns, or escalation request
  - `Memory worker`
    - on task completion, evidence ingestion, or context-budget pressure

### 11.9 Evidence-Backed Reasoning Plan

- Every important agent conclusion should reference structured evidence
- Evidence records should support:
  - source type
  - source reference/ID
  - target binding
  - timestamp
  - confidence
  - freshness
  - verification state

- Agents should emit:
  - candidate hypotheses
  - confidence updates
  - next verification actions
  - promotion/demotion proposals

- Agents should not emit durable facts from unsupported intuition alone

### 11.10 Context Management Plan

- Context must be layered and role-scoped:
  - `task context`
  - `shared working context`
  - `episodic memory`
  - `semantic memory`

- `Task context`
  - minimum material for one bounded task
  - disposed after completion

- `Shared working context`
  - active interests
  - top unresolved hypotheses
  - recent verified evidence
  - current operator directives

- `Episodic memory`
  - per-task summaries and notable outcomes

- `Semantic memory`
  - durable validated facts and recurring patterns

- Retrieval rules:
  - load only the slice needed for the current role
  - prefer references and summaries over raw artifact dumps
  - rebuild task context on demand rather than carrying giant prompts forward

### 11.11 Inter-Agent Communication Plan

- Agents should communicate via structured handoff objects rather than freeform transcript sharing
- Minimum handoff fields:
  - task ID
  - source agent
  - destination agent
  - handoff reason
  - evidence references
  - current hypothesis/question
  - expected output type
  - budget/deadline

- Default routing:
  - orchestrator -> specialist
  - specialist -> orchestrator
  - specialist -> memory worker
  - verifier -> orchestrator

- Specialist-to-specialist direct handoff should be exceptional and justified by latency or cost
- Raw artifacts should be shared only when summaries and references are insufficient

### 11.12 Communication Efficiency Rules

- Share evidence references before raw blobs
- Share compressed summaries before full transcripts
- Share confidence changes and blockers, not only conclusions
- Require verification tasks before accepting chained exploit claims
- Apply budget caps to chaining and deep-review branches

## 12. Research-Informed Design Notes

- `Policy enforcement`
  - Research and production systems suggest using an explicit policy engine instead of relying on prompt instructions alone
  - Candidate implementation directions:
    - `OPA`
    - `Cedar`

- `Memory hierarchy`
  - Research and open-source systems support hierarchical memory with promotion, compaction, and retrieval
  - Relevant references:
    - `MemGPT / Letta`
    - `A-MEM`
    - `SimpleMem`

- `Contradiction and invalidation`
  - Memory systems need explicit contradiction checks, verification state, and supersession/invalidation paths
  - Relevant reference:
    - `MQUAKE / MeLLo`

- `Durable orchestration`
  - Long-running agents should be implemented as replayable workflows with checkpoints and resumability
  - Relevant implementation references:
    - `Temporal`
    - `Conductor`
    - `LangGraph`

- `Agent verification`
  - Verification should combine traces, deterministic metrics, and optional LLM judging
  - Relevant implementation references:
    - `agentevals`
    - `OpenLIT`
    - `OpenLLMetry`
    - `traceAI`

- `Planning realism`
  - Academic results continue to show that LLM planning is not strong enough to trust without structure, constraints, and external state
  - Relevant papers:
    - `ReAct`
    - `PlanBench`

- `Security-specific multi-agent support`
  - Security papers suggest that specialist decomposition can improve exploit-path reasoning and long-horizon work
  - Relevant paper:
    - `Teams of LLM Agents can Exploit Zero-Day Vulnerabilities`

## 13. Architecture Corrections

### 13.1 Required Components

- `Action-policy engine`
  - Every non-trivial tool action must be evaluated against deterministic policy before execution
  - Policy must support:
    - scope binding
    - target/profile-aware restrictions
    - methodology-phase restrictions
    - rate/concurrency caps
    - approval requirements
    - exploit-depth limits
    - stop conditions
  - Candidate implementation directions:
    - `OPA`
    - `Cedar`

- `Durable workflow engine`
  - The orchestrator should run on top of replayable durable workflows rather than a fragile endless agent loop
  - Required features:
    - task queues
    - leases
    - retries
    - heartbeats
    - resumability
    - checkpoint/replay
  - Candidate implementation directions:
    - `Temporal`
    - `Conductor`
    - `LangGraph` only if wrapped with stronger operational guarantees

- `Memory service`
  - Memory must be a first-class subsystem, not an emergent property of prompts
  - Required capabilities:
    - working / episodic / semantic layers
    - promotion and demotion
    - contradiction handling
    - supersession/invalidation
    - retrieval ranking
    - freshness decay
    - target/program scoping

- `Evidence and provenance layer`
  - All important claims must resolve to structured evidence records
  - Required capabilities:
    - source references
    - timestamps
    - verification state
    - contradiction links
    - fact-to-evidence lineage

- `Observability and deterministic verification layer`
  - Agent verification must not rely only on another LLM
  - Required capabilities:
    - trace capture
    - repeated-action detection
    - retry-storm detection
    - unsupported-claim detection
    - cost/latency tracking
    - recovery tracking after failures
  - LLM judging should be optional and secondary

- `Model scheduler`
  - The runtime must explicitly arbitrate hot-path GPU use
  - Required capabilities:
    - one-primary-hot-model scheduling
    - cold-path reviewer dispatch
    - queueing/preemption rules
    - escalation routing
    - cache residency awareness

- `Tooling substrate`
  - The system must absorb a large and evolving set of cyber tools/scripts without exposing raw chaos to the model
  - Required capabilities:
    - tool catalog with manifests
    - primitive wrapper generation
    - capability taxonomy
    - install and health checks
    - per-tool auth/secret requirements
    - side-effect and risk classification
    - sandbox/container execution profiles
    - output normalization
    - evidence extraction adapters
    - tool bundling by methodology/profile

### 13.2 Architecture Shifts

- Shift from:
  - “multi-agent system with good prompts”
- Shift to:
  - deterministic workflow engine with model-assisted workers

- Shift from:
  - “context window as working memory”
- Shift to:
  - memory service with retrieval, compaction, and invalidation

- Shift from:
  - “LLM decides if it is safe”
- Shift to:
  - policy engine approves or denies actions

- Shift from:
  - “another LLM checks the first LLM”
- Shift to:
  - traces plus deterministic checks, with optional LLM review

### 13.3 Non-Negotiable Invariants

- No risky action without explicit policy evaluation
- No durable fact without evidence, provenance, confidence, and freshness metadata
- No exploit chain is accepted without bounded verification tasks succeeding
- No agent receives the full engagement history by default
- No task branch may continue indefinitely without checkpointing and replayable state
- No high-confidence claim may exist without traceable evidence support
- No contradiction may be silently ignored; durable facts must support supersession/invalidation
- No heavy GPU specialist may assume permanent residency on the `12GB` hot path

### 13.4 Immediate Design Consequences

- The methodology engine must compile to policy-constrained workflow states, not freeform prompts
- The hypothesis / analysis phase should be decomposed into executable subphases:
  - anomaly triage
  - hypothesis generation
  - prerequisite resolution
  - exploit-path ranking
- The vulnerability chaining agent should output:
  - candidate chains
  - missing prerequisites
  - verification tasks
  - confidence deltas
- The memory worker must support contradiction-aware compaction instead of summary-only compression
- The verifier must consume both agent traces and evidence lineage
- The tooling layer must route agents through capability abstractions and manifests, not ad hoc shell access
- Tool onboarding must be cheap enough that existing recon and pentest scripts can be integrated incrementally

### 13.5 Suggested Implementation Order

1. Build the evidence schema, task schema, and memory schema.
2. Add the durable workflow layer and task lifecycle.
3. Add the deterministic policy engine and approval matrix.
4. Add observability, tracing, and deterministic verifier checks.
5. Add the hot-path model scheduler and cold-path reviewer routing.
6. Add specialist agents only after the control plane is working.

## 14. Quality Attributes

- Reliability over novelty
- Determinism where possible
- Strong auditability
- Cost awareness
- Local-first operation
- Clear human override
- Strict policy enforcement

## 15. Risks

- Local-model reasoning quality may be insufficient for complex authz and business-logic issues
- Over-automation may create noisy or repetitive work
- Context compaction may accidentally discard useful nuance
- Too many primitives may degrade routing quality
- Scope normalization may become error-prone if asset metadata is inconsistent
- Small local models may appear competent while still failing on the exact high-value edge cases that matter most in bounty work
- Long-running agent confidence may drift upward faster than actual evidence quality if verification is not enforced

## 16. Open Design Questions

- Preferred implementation stack
- Exact note schema
- Exact interest lifecycle
- Best provider abstraction for Claude-agent support
- Which methodologies ship first
- Which tasks require approval by default
- How to measure usefulness of AI-managed notes/context
- How memory promotion/expiration should work
- Whether to support adapter fine-tuning in product or as an external pipeline
- What exact memory schema and retrieval index should back “continuous learning”

## 17. Early Success Criteria

- Import a scope and display normalized assets
- Select a methodology and launch bounded tasks
- Persist tasks, notes, evidence, and interests across restarts
- Run continuously for extended periods without context collapse
- Escalate a task to Claude-agent mode successfully
- Produce useful compact notes that improve downstream task quality
- Show measurable reduction in prompt size via memory compaction without loss of key evidence

## 18. Feasibility Assessment

- `Overall assessment`
  - The project is technically feasible if built as a control-plane product with model-assisted workers
  - The project is not currently realistic if framed as a mostly unattended all-local replacement for top premium reasoning models

- `Most realistic win condition`
  - a durable semi-autonomous platform for scope-aware recon, triage, evidence handling, note/context management, bounded verification, and selective deep-review escalation

- `Most difficult technical areas`
  - tooling substrate and output normalization
  - memory quality over long runtimes
  - deterministic policy enforcement
  - contradiction/invalidation handling
  - verification of agent behavior
  - long-horizon exploit-path reasoning

- `Rough probability bands`
  - useful v1 operator platform: `75-85%`
  - good continuous recon/triage/verification assistant: `60-75%`
  - reliable multi-day semi-autonomous workflow engine: `55-70%`
  - strong vuln chaining and exploit-path assistant: `40-60%`
  - mostly autonomous bounty-grade bug hunter: `20-35%`
  - all-local replacement for premium-model reasoning: `10-20%`

- `Interpretation`
  - The architecture is strong enough to justify building
  - Success depends on narrowing the initial target, enforcing policy and observability early, and treating tooling/memory as the real product

### 18.1 Cost and Token Estimate

- `Pricing basis`
  - For automated operation, compare against Anthropic API pricing rather than Claude Max chat-plan pricing
  - Planning assumptions:
    - `Claude Sonnet 4`: `$3 / MTok` input, `$15 / MTok` output
    - `Claude Opus 4.1`: `$15 / MTok` input, `$75 / MTok` output
  - Prompt caching can lower repeated input-context cost, but does not remove the cost of output-heavy hard reasoning

- `Expected effect of the proposed architecture`
  - By keeping broad routine work local and sending only sparse high-value tasks to Claude:
    - expected Claude token reduction: roughly `80-95%`
    - expected Claude cost reduction vs all-Claude Sonnet: roughly `70-90%`
    - expected Claude cost reduction vs all-Claude Opus: roughly `85-95%`

- `Interpretation`
  - The main savings come from not spending premium tokens on:
    - recon noise
    - note maintenance
    - context compaction
    - repetitive triage
    - routine script/tool glue
  - Premium spend is concentrated on:
    - stuck-task rescue
    - exploit synthesis
    - subtle vulnerability judgment
    - high-value finding review

### 18.2 ROI Assessment

- `Solo operator / bounty workflow`
  - ROI is moderate
  - Best returns come from:
    - saving time on recon, triage, note management, and evidence handling
    - reducing context loss across multi-day work
    - reducing premium-model spend
  - Poor ROI if the initial expectation is autonomous elite-quality bug discovery

- `Internal security / repeated program use`
  - ROI is high
  - The tooling substrate, workflow engine, and memory system become more valuable with repeated use across targets and teams

- `Strategic product value`
  - ROI is potentially high if differentiation comes from:
    - durable workflows
    - controlled tooling integration
    - evidence-backed memory
    - selective premium-model augmentation
  - ROI is poor if the product is framed primarily as a generic multi-agent wrapper

- `Bottom-line judgment`
  - Good investment if the project is pursued as an operator platform
  - Risky investment if pursued first as a mostly autonomous bounty machine

### 18.3 Execution Confidence

- `Buildability`
  - The project is buildable in phases
  - It should not be treated as a single-shot implementation effort

- `High-confidence implementation areas`
  - control plane
  - durable workflows
  - storage and artifact handling
  - primitive registry/tooling substrate
  - memory/evidence schemas
  - Notion/Discord integration
  - Claude augmentation and rescue flows

- `Higher-risk implementation areas`
  - trustworthy long-horizon autonomous reasoning
  - reliable exploit synthesis quality
  - high-signal vulnerability chaining with low hallucination rates
  - taming a large heterogeneous security toolchain without iterative operational hardening

- `Execution implication`
  - The right path is a staged build with aggressive scope control, not an attempt to deliver the full vision in one pass

### 18.4 Build Budget Feasibility

- `800 credits budget`
  - Likely sufficient for a disciplined narrow v1
  - Not sufficient for the full platform vision

- `1400 credits budget`
  - Likely sufficient for a strong v1 plus selective v1.5 features
  - Still not sufficient for the entire long-term platform vision

- `Reasonable within budget`
  - repo bootstrap
  - core architecture and schemas
  - TUI skeleton
  - storage/artifact layer
  - primitive registry and manifests
  - one host/container execution lane
  - basic memory/evidence flow
  - Claude escalation path
  - Notion/Discord basic integration
  - one or two real worker paths

- `Unreasonable within budget`
  - broad toolchain onboarding
  - polished exploit-synthesis loops
  - mature low-hallucination chaining
  - extensive hardening
  - broad target-profile coverage
  - production-quality validation across many tools and workflows

- `Implication`
  - If the build is pursued under this budget, v1 scope must stay narrow and operationally useful rather than ambitious

- `Reasonable with 1400 credits`
  - stronger v1 core
  - additional worker paths
  - more capable tooling substrate
  - initial chaining support
  - more polished Claude augmentation
  - better tests and cleanup

- `Still unrealistic with 1400 credits`
  - broad heterogeneous tool onboarding at scale
  - highly polished exploit-generation quality
  - mature autonomy across many target classes
  - heavy hardening and validation across a wide operational surface

## 19. Next Draft Areas

- Concrete architecture
- Storage design
- Provider interface
- Primitive registry format
- Note/context compaction pipeline
- TUI screen definitions

## 20. Component Diagram Draft

### 20.1 High-Level Component View

```text
[Operator / TUI]
        |
        v
[Workflow Orchestrator] ---> [Policy Engine]
        |
        +----> [Task Queue / Scheduler] ---> [Agent Workers]
        |                                      |  recon
        |                                      |  hypothesis / analysis
        |                                      |  exploitation
        |                                      |  chaining
        |                                      |  memory
        |                                      |  behavior verifier
        |
        +----> [Model Router / Scheduler] ---> [Local GPU Models]
        |                                      [Local CPU Models]
        |                                      [Claude / Remote Provider]
        |
        +----> [Primitive Registry / Executor] ---> [Caido]
        |                                           [Scanners / Scripts]
        |                                           [Adapters]
        |
        +----> [Memory Service] ---> [Working Memory]
        |                           [Episodic Memory]
        |                           [Semantic Memory]
        |                           [Vector / Retrieval Index]
        |                           [Notion Sync Layer]
        |
        +----> [Evidence / Notes / Interests Store]
        |
        +----> [Tracing / Metrics / Event Log]
        |
        +----> [Discord Notification Layer]
```

### 20.2 Responsibility Boundaries

- `Operator / TUI`
  - imports scope
  - selects methodology
  - reviews findings, chains, and approvals
  - overrides or pauses automation

- `Workflow orchestrator`
  - owns lifecycle, task state, retries, and resumability
  - is the only always-on cognitive controller

- `Policy engine`
  - authorizes or denies actions before execution
  - enforces scope, phase, rate, approval, and stop conditions

- `Task queue / scheduler`
  - dispatches bounded tasks
  - enforces concurrency and priority

- `Agent workers`
  - perform narrow roles
  - emit evidence-backed outputs, not freeform global state

- `Model router / scheduler`
  - chooses local-fast, local-deep, local-code, local-compact, or remote-premium
  - arbitrates single-GPU hot-path usage

- `Primitive registry / executor`
  - exposes typed tools and scripts as controlled primitives
  - records side effects, outputs, and evidence lineage
  - resolves capability requests into approved concrete tools/primitives

- `Memory service`
  - manages retrieval, promotion, demotion, contradiction handling, and compaction
  - publishes operator-facing note views to Notion without making Notion the source of truth

- `Evidence / notes / interests store`
  - persists the normalized record of what the system knows and why it thinks it knows it

- `Tracing / metrics / event log`
  - provides deterministic verification and operational observability

- `Discord notification layer`
  - emits filtered high-signal alerts tied back to internal records

## 21. Minimal V1 Architecture Stack

### 21.1 V1 Goal

Build the smallest version that can:

- import scope
- run bounded methodology tasks
- preserve evidence and memory across restarts
- enforce policy
- compact context continuously
- escalate selectively to stronger models
- remain inspectable during multi-day operation
- sync readable per-target notes to Notion
- notify Discord on important events

### 21.2 Recommended V1 Stack

- `Frontend / UX`
  - terminal-native TUI
  - focus on dashboard, scope view, task queue, notes/interests, findings, and approvals

- `Workflow / control plane`
  - durable workflow runtime
  - queue-driven task execution
  - checkpoint and replay support

- `Policy layer`
  - deterministic policy engine separate from prompts
  - target/profile/methodology-aware action rules

- `Storage`
  - relational store for tasks, evidence, notes, interests, findings, and policy decisions
  - append-only event log
  - artifact store on NVMe for replays, raw outputs, and snapshots
  - vector index for retrieval over notes/evidence
  - external sync metadata for Notion and Discord delivery state

- `Model layer`
  - one GPU hot-path generalist model
  - one GPU deep-reasoning specialist on demand
  - one GPU code/tooling specialist on demand
  - one CPU memory-compaction model
  - optional larger CPU reviewer tier
  - optional Claude escalation adapter

- `Tooling layer`
  - typed primitive registry
  - primitive executor
  - tool catalog with manifests
  - output normalization adapters
  - tool health checks
  - bundle/profile filtering
  - Caido connector
  - scanner/script adapters

- `Memory layer`
  - working memory
  - episodic memory
  - semantic memory
  - contradiction and invalidation support
  - automatic compaction rules
  - Notion publishing/sync adapter for operator-facing note views

- `Observability layer`
  - agent/task traces
  - cost and latency metrics
  - retry/loop detection
  - unsupported-claim checks
  - recovery-state tracking
  - Discord notification policy and delivery

### 21.2.1 Deployment Recommendation

- Recommended model: `hybrid containerization`

- `Containerize the core platform`
  - Postgres
  - workflow/control-plane services
  - sync/notification services
  - many bounded workers
  - optionally model-serving components

- `Allow host-native execution lanes`
  - for primitives that require:
    - host networking behavior
    - privileged access
    - packet capture
    - unusual kernel/device access
    - brittle GPU/runtime coupling

- `Reasoning`
  - Containerization helps reproducibility, dependency isolation, and service deployment
  - But forcing every security tool into containers adds friction around networking, privileges, filesystem access, and GPU/runtime integration
  - Therefore the system should support both:
    - containerized workers
    - host-executed primitives

- `Practical default`
  - start with containerized core services
  - keep an escape hatch for host execution of difficult tools

### 21.3 Recommended Implementation Language

- `Primary language`
  - `Python 3.12+`

- `Why Python is the best fit for v1`
  - strongest ecosystem for local-model orchestration, embeddings, retrieval, and memory tooling
  - official `Textual` support for a serious terminal-native TUI
  - official `Temporal Python SDK` support for durable workflows
  - easier iteration for schema-heavy orchestration and trace-aware control-plane work

- `Where TypeScript may still exist`
  - a narrow Caido adapter/plugin boundary if a native Caido integration is materially easier in JavaScript/TypeScript
  - provider-specific adapters where an SDK surface is better maintained outside Python

- `What to avoid`
  - do not make the entire project TypeScript-first solely because Caido plugin development is JavaScript-based
  - do not split the core control plane across multiple languages unless the integration boundary is very clear

### 21.4 Minimal V1 Agent Set

- `Orchestrator`
  - always on

- `Recon worker`
  - event-driven

- `Hypothesis / analysis worker`
  - event-driven

- `Exploitation worker`
  - event-driven and policy-gated

- `Memory worker`
  - timer-driven and event-driven

- `Behavior verifier`
  - event-driven, cheap, frequent

The chaining worker can be added in early v1.5 if the control plane is stable, or in v1 if exploit-path reasoning is central from day one.

### 21.5 Suggested V1 Data Backbone

- `Core tables / entities`
  - targets
  - scope_assets
  - tasks
  - task_runs
  - evidence
  - notes
  - interests
  - findings
  - memory_entries
  - policy_decisions
  - agent_traces
  - artifacts
  - tools
  - tool_versions
  - tool_manifests
  - tool_health_checks
  - tool_bundles
  - notifications
  - external_sync_jobs
  - notion_pages
  - discord_deliveries

- `Core IDs and links`
  - every task links to scope, phase, agent, evidence, and policy decision
  - every durable memory item links back to evidence lineage
  - every finding candidate links to verification state

### 21.5.1 Recommended Storage Map

- `PostgreSQL`
  - canonical live operational store
  - best fit for:
    - tasks and workflow state
    - notes, interests, findings
    - evidence metadata
    - memory entries
    - policy decisions
    - notification and external-sync state
  - reasons:
    - strong relational integrity
    - JSONB support for flexible structured payloads
    - full-text search
    - mature concurrency for multi-worker systems

- `pgvector in PostgreSQL`
  - default retrieval/embedding layer
  - best fit for:
    - note embeddings
    - evidence-summary embeddings
    - finding/memory retrieval
  - preferred initially over a separate vector database because the project benefits from keeping vectors and relational records together

- `Filesystem on NVMe`
  - raw artifact store
  - best fit for:
    - large request/response bodies
    - replay exports
    - screenshots
    - scanner raw outputs
    - generated exploit files
    - checkpoints and snapshots
  - rule:
    - keep heavy blobs in files
    - keep metadata, hashes, paths, and lineage in SQL

- `Parquet + DuckDB`
  - cold analytics and archive layer
  - best fit for:
    - historical logs
    - large event exports
    - offline analytics
    - engagement summaries
    - trend analysis over long time windows
  - not the primary online transactional store

- `SQLite`
  - not recommended as the primary live control-plane store
  - acceptable for:
    - portable case bundles
    - debug exports
    - local single-file snapshots
    - very small auxiliary caches

### 21.6 V1 Sequence

1. Operator imports scope and selects methodology.
2. Orchestrator creates bounded tasks.
3. Policy engine gates each non-trivial action.
4. Workers resolve capability requests into approved primitives via the tool catalog.
5. Workers execute through typed primitives and Caido integrations.
6. Raw tool outputs are normalized into evidence-bearing records.
7. Outputs become evidence, notes, and interests.
8. Memory worker compacts and promotes/demotes records.
9. Operator-facing note views are synced to per-target Notion pages/subtrees.
10. Verifier checks traces and evidence support.
11. High-signal events are emitted to Discord when policy says they matter.
12. Stronger models are used only when escalation criteria are met.
13. System checkpoints state continuously and resumes cleanly after interruption.

## 23. Notion and Discord Integration Plan

### 23.1 Notion Role

- Notion should be the human-facing notes workspace
- The system should generate and maintain a structured target-centric subtree in Notion
- Each bug bounty target or HTB target should have its own page/folder-like subtree
- Suggested per-target structure:
  - overview
  - notes
  - evidence links
  - findings
  - open hypotheses
  - next actions

### 23.2 Source of Truth Rule

- Notion must not be the canonical store
- Canonical state remains in local structured storage
- Notion pages should be generated/synced views over canonical notes, findings, and evidence links
- This avoids state drift and makes recovery/rebuild possible

### 23.3 Notion Sync Behavior

- Sync after meaningful note/finding updates rather than every tiny state change
- Support idempotent page creation and update
- Track external sync state and failures
- Avoid dumping raw noisy artifacts directly into Notion
- Prefer concise human-readable summaries with links back to canonical records

### 23.4 Discord Role

- Discord should be a filtered alerting channel, not a full audit log
- Use it to pull operator attention when something important happens
- Likely events:
  - report-worthy finding candidate
  - major confidence or severity change
  - approval needed
  - workflow failure requiring intervention
  - Claude review materially changes direction

### 23.5 Discord Message Shape

- Target/program identifier
- concise event summary
- confidence or severity change if relevant
- urgency level
- link/reference back to the internal record or TUI-visible task

### 23.6 Guardrails

- Rate-limit noisy notifications
- Deduplicate near-identical alerts
- Respect operator preferences and severity thresholds
- Never treat Discord delivery as durable storage

## 22. Tooling Substrate Plan

### 22.1 Tooling Philosophy

- The product should treat tools as a managed substrate, not a pile of scripts
- The LLM should reason about capabilities and constraints, not shell syntax and binary names
- Existing tools should be integrated through wrappers/manifests whenever possible instead of rewritten

### 22.2 Tool Manifest Requirements

Each onboarded tool should have a manifest describing at minimum:

- canonical name
- version
- description
- capability tags
- methodology phases
- input schema
- output schema or parser
- side-effect level
- risk tier
- required secrets/auth
- timeout and resource hints
- retry policy
- evidence adapter
- sandbox/container profile
- health-check command

### 22.3 Tool Catalog and Routing

- Maintain a catalog of available tools and versions
- Support capability-based lookup such as:
  - subdomain enumeration
  - HTTP probing
  - content discovery
  - parameter mining
  - diffing
  - screenshotting
  - JS extraction
  - auth analysis
  - finding verification
- Agents should request a capability and constraints
- The orchestrator/tool router chooses the concrete primitive/tool

### 22.4 Output Normalization

- Raw tool outputs should rarely go straight into prompts
- Every noisy tool should have a normalizer/parser where practical
- Normalized outputs should become:
  - evidence records
  - notes
  - interests
  - metrics
  - follow-up task candidates

### 22.5 Safety and Control

- Tools must be classified by risk and side effects
- Higher-risk tools should require stricter policy checks or approvals
- Tools with unstable output should be marked lower-trust
- Secret-bearing tools must declare their requirements explicitly
- Potentially dangerous tools should support restricted sandbox profiles

### 22.6 Tool Bundles and Profiles

- Support bundles/profiles for:
  - recon
  - web content discovery
  - JS analysis
  - auth/session workflows
  - cloud/API workflows
  - HTB-specific workflows
  - H1 program-safe workflows

- This allows methodology and target profiles to expose only relevant capabilities

### 22.7 V1 Tooling Scope

- V1 should not attempt to integrate every tool
- V1 should prove the substrate with:
  - manifest format
  - wrapper contract
  - capability routing
  - health checks
  - output normalization
  - evidence extraction
  - bundle/profile filtering
