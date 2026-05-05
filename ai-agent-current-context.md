# AI Agent TUI - Current Context

Last updated: 2026-05-04
Status: Active working notes for this conversation

## Latest Tracking Update

- User clarified that the machine has enough RAM to keep multiple models preloaded
- This changes the design toward a two-lane runtime:
  - fast hot-path models for nonstop orchestration
  - slower cold-path reviewer models in RAM for scheduled deep analysis
- Larger CPU-resident models should be treated as periodic judges/reconcilers, not as the main always-on loop
- User also clarified the NVMe is extremely fast and suitable for heavy AI-adjacent I/O workloads

## Purpose

This file tracks the live context for the planning conversation. It should stay short, current, and operational.

## Current Goal

Design a CLI/TUI application that manages and orchestrates AI agents for authorized cybersecurity workflows, with strong context management, note management, tool orchestration, and long-running reliability.

## Current User Intent

- Include an option to use Claude agents because they perform well for this problem class
- Expect a large collection of external cyber recon, pentesting, and analysis tools/scripts to be integrated over time
- Use `Notion` as the operator-facing notes workspace
- Organize notes so each bug bounty target or HTB target gets its own folder-like area/subtree in Notion
- Send high-signal notifications to `Discord` when important events happen

## Product Direction So Far

- Primary interface: TUI/CLI
- Primary use case: long-running, continuous authorized testing against a provided scope
- Scope input sources:
  - HackerOne scope lists and files
  - Hack The Box targets/labs
- Methodology-driven execution:
  - User selects or configures a methodology from a TUI menu
  - An orchestrator decides which admissible step to run next
- AI should also manage notes and context, not only tool execution
- Context compaction and instruction management are first-class requirements
- Tool integration must prevent overwhelming the LLM with too many raw scripts
- The product needs a real tooling substrate for onboarding, cataloging, routing, normalizing, and controlling many external tools
- Notion should be the human-facing notes surface, but local structured storage should remain the source of truth
- Proposed methodology phases now under consideration:
  - recon
  - hypothesis / analysis
  - exploitation
  - chaining
  - verification of agent behavior

## Architecture Leanings

- Use a deterministic orchestration layer rather than one freeform always-on agent
- Prefer short-lived task workers over one giant multi-day prompt session
- Keep state in durable storage and reload context per task
- Use Caido as the source of truth for HTTP traffic, replay, findings, and related testing artifacts where applicable
- Wrap tools/scripts as typed primitives with clear schemas

## Model Strategy Leanings

- Local-first by default
- GPU-backed primary reasoning/planning model
- CPU-backed smaller model for note cleanup, summarization, clustering, tagging, and context compaction
- Optional Claude agent mode for difficult reasoning and higher-quality security analysis
- Claude should act as a selective augmentation layer for weaker local models, not only as a final fallback
- Cloud usage should be policy-controlled and cost-aware

## Local Model Guidance So Far

- The RTX 5070 12GB should comfortably handle strong `7B-8B` class models and some `12B-14B` models when quantized, with tradeoffs in speed and context pressure
- The CPU/RAM combination is strong enough for a second smaller model dedicated to summarization, tagging, memory cleanup, note compaction, and background classification
- Best likely split for v1:
  - GPU model for planning, orchestration, and hard task reasoning
  - CPU model for compression, ranking, dedupe, and maintenance work
- Candidate local families currently under consideration:
  - `Qwen3`
  - `Qwen2.5`
  - `Qwen2.5-Coder`
  - `DeepSeek-R1` distilled small variants
  - `Gemma 3`
  - `Phi-4-mini`
  - Optional larger quantized coding/reasoning models if latency is acceptable
- Current recommended shortlist:
  - GPU default orchestrator: `gemma3:12b`
  - GPU deep-reasoning escalation: `deepseek-r1:8b`
  - GPU code/tool synthesis: `qwen2.5-coder:7b`
  - CPU note/context compactor: `phi4-mini`
  - CPU richer note summarizer alternative: `gemma3:4b`
- Models currently considered less optimal for nonstop use on this hardware:
  - `codestral:22b`
  - `mistral-small:24b`
  - `32B+` variants in general

## Continuous Learning Direction So Far

- Do not treat “learning” as keeping everything in prompt context
- The system should learn through structured memory and periodic adaptation layers
- Preferred layers:
  - Episodic memory: per-task notes, evidence, replays, failures, successful chains
  - Semantic memory: stable summaries, target facts, auth patterns, repeated bug classes, methodology hints
  - Working memory: bounded task-specific context loaded on demand
  - Optional offline adaptation: periodic dataset creation from approved traces for later fine-tuning or adapter tuning
- AI-managed notes are part of the learning loop:
  - summarize
  - dedupe
  - cluster
  - relink
  - expire stale items
  - promote durable facts only when verified
- “Continuous learning” in v1 should mean:
  - continuous note refinement
  - continuous memory promotion/demotion
  - continuous retrieval improvement
  - optional offline tuning/export later
- It should not mean live weight updates during active runs

## Runtime Matrix Draft

- `gemma3:12b` on GPU
  - Role: primary orchestrator / planner
  - Handles:
    - methodology navigation
    - next-step selection
    - task decomposition
    - broad hypothesis generation
    - note-aware prioritization
  - Expected use:
    - VRAM: about `8-10GB` practical quantized footprint depending on runtime/config
    - System RAM spill/offload may increase if context is pushed hard
  - Weaknesses:
    - may overgeneralize weak signals
    - not reliable enough for final vuln judgment on subtle issues

- `deepseek-r1:8b` on GPU
  - Role: hard-reasoning escalation worker
  - Handles:
    - tricky hypothesis evaluation
    - multi-step chain reasoning
    - exploit-path plausibility checks
    - conflict resolution between notes/evidence
  - Expected use:
    - VRAM: about `5-7GB` practical quantized footprint
  - Weaknesses:
    - slower/more verbose reasoning
    - can still be confidently wrong on real-world app nuance

- `qwen2.5-coder:7b` on GPU
  - Role: code and primitive authoring worker
  - Handles:
    - script generation
    - parser/transformation code
    - tool wrappers
    - test harnesses
  - Expected use:
    - VRAM: about `5-6GB` practical quantized footprint
  - Weaknesses:
    - narrower strength profile
    - should not be the main orchestrator

- `phi4-mini` on CPU
  - Role: memory compactor / notes manager / classifier
  - Handles:
    - note condensation
    - dedupe
    - interest tagging
    - confidence labeling
    - memory promotion candidates
    - stale-memory pruning proposals
  - Expected use:
    - RAM: about `4-8GB` practical range depending on runtime/batch/settings
  - Weaknesses:
    - not suitable for difficult vulnerability reasoning

- `gemma3:4b` on CPU or fallback GPU
  - Role: richer summarizer alternative
  - Handles:
    - better note synthesis than ultra-small models
    - compact evidence summaries
    - cross-note linking
  - Expected use:
    - RAM: about `6-10GB` practical range on CPU
  - Weaknesses:
    - more latency than `phi4-mini`

- Larger CPU-resident models are also viable on this hardware
  - Use case:
    - low-frequency reviewer/judge roles
    - nightly reconciliation
    - deeper cross-target synthesis
    - methodology postmortems
    - promotion review for high-value findings
  - Important constraint:
    - these should not sit in the hot path of the nonstop orchestration loop

- Recommended CPU-side larger-model tier
  - `gemma3:27b`
    - good candidate for slower high-quality synthesis/review
  - `qwen2.5:32b`
    - good candidate for heavier structured reasoning/review
  - `deepseek-r1:32b`
    - good candidate for very selective hard reasoning review
  - `llama3.1:70b`
    - possible in RAM with aggressive quantization/offload, but likely too slow for regular use

## Hot Path vs Cold Path Guidance

- Hot path:
  - must stay responsive
  - uses GPU primary models and small CPU memory workers
  - handles continuous orchestration and compaction

- Cold path:
  - can be slow
  - uses larger CPU-resident reviewers
  - handles checkpoint review, dispute resolution, deep synthesis, and periodic memory rebuilds

## Proposed Additional Agent Role

- `Vulnerability chaining agent`
  - Purpose:
    - identify how individually weak observations may combine into a real exploit path
    - reason over prerequisite relationships between findings, auth state, trust boundaries, and workflow transitions
    - surface candidate multi-step chains without prematurely calling them valid
  - Best operating mode:
    - not always-on in the hot path
    - triggered only when enough evidence exists or when multiple interests appear related
    - outputs candidate chains, missing prerequisites, and verification tasks
  - Guardrails:
    - cannot mark a chain as valid without verification tasks succeeding
    - should consume structured evidence, not raw long transcripts
    - should be budget-limited because chaining work can expand combinatorially

## Proposed Methodology Flow

- `Recon`
  - collect targets, endpoints, behaviors, parameters, auth surfaces, and artifacts

- `Critical thinking`
  - cluster observations, identify anomalies, generate hypotheses, rank likely attack paths

- `Exploitation`
  - run bounded verification tasks against prioritized hypotheses

- `Chaining`
  - combine verified or partially verified primitives into multi-step exploit candidates

- `Verification of agent behavior`
  - audit agent decisions, tool use, duplication, confidence inflation, loops, and unsupported claims

## Current Opinion on This Addition

- Adding a chaining agent is a good idea if:
  - it is treated as a selective specialist
  - it operates on structured evidence
  - it produces verification tasks rather than final claims

- It is a bad idea if:
  - it runs constantly
  - it is allowed to speculate without tight gating
  - it becomes another freeform agent with too much tool access

## Event-Driven and Evidence-Backed Plan

- Agents should not run continuously just because they exist
- Every specialist agent should be activated by explicit triggers
- Every important claim should be tied to structured evidence objects
- Agent outputs should prefer:
  - candidate hypotheses
  - ranked next actions
  - verification tasks
  - confidence changes
  - memory promotion proposals

## Trigger Plan by Agent

- `Primary orchestrator`
  - Trigger:
    - always active as the scheduler/controller
    - wakes on new scope, finished task, failed task, timer tick, or operator action

- `Recon workers`
  - Trigger:
    - new target
    - stale target needing refresh
    - new auth/session artifact
    - methodology phase entry into recon

- `Critical thinking worker`
  - Trigger:
    - enough new evidence accumulated
    - anomaly cluster detected
    - unresolved hypothesis backlog exceeds threshold

- `Exploitation worker`
  - Trigger:
    - prioritized hypothesis with required prerequisites present
    - operator approval if policy requires it

- `Vulnerability chaining worker`
  - Trigger:
    - two or more related verified interests
    - repeated co-occurrence across notes/evidence
    - unresolved exploit candidate with partial prerequisites

- `Agent-behavior verifier`
  - Trigger:
    - high-confidence claim
    - repeated retry loop
    - duplicate task pattern
    - premium-model escalation request
    - final finding candidate

- `Memory / notes worker`
  - Trigger:
    - task completion
    - large evidence ingestion
    - timer-based maintenance
    - context budget threshold crossing

## Evidence Requirements

- Each claim should reference one or more evidence records
- Evidence types may include:
  - Caido replay/reference IDs
  - request/response fingerprints
  - endpoint/parameter/auth artifacts
  - scanner outputs
  - code/tool outputs
  - operator notes

- Each evidence-backed claim should carry:
  - source references
  - timestamp
  - target scope binding
  - confidence score
  - freshness score
  - verification status

- No agent should promote a durable fact from:
  - raw intuition alone
  - a single weak unverified clue
  - unsupported chain speculation

## Context Management Plan

- Use strict layered context:
  - `task context`
  - `shared working context`
  - `episodic memory`
  - `semantic memory`

- `Task context`
  - only the minimum needed for one bounded task
  - expires when the task finishes

- `Shared working context`
  - active interests
  - top unresolved hypotheses
  - recent verified evidence
  - short operator directives

- `Episodic memory`
  - per-task summaries
  - failures
  - successful exploit attempts
  - important tool outputs

- `Semantic memory`
  - durable target facts
  - recurring auth patterns
  - validated attack paths
  - methodology heuristics

- Context loading rule:
  - agents should pull only role-relevant context slices
  - no agent should receive the full project history by default

## Communication and Sharing Plan

- Agents should communicate through structured handoff objects, not open-ended chat
- Handoff object should include:
  - task ID
  - source agent
  - target agent
  - reason for handoff
  - relevant evidence references
  - current hypothesis or question
  - expected output type
  - deadline/budget

- Allowed communication patterns:
  - orchestrator -> specialist
  - specialist -> orchestrator
  - specialist -> memory worker
  - verifier -> orchestrator

- Direct specialist-to-specialist communication should be limited
  - prefer routing through the orchestrator unless latency/cost justifies a direct structured handoff

- Sharing rules:
  - share summaries and evidence references first
  - share raw artifacts only when the receiving agent truly needs them
  - share confidence deltas, not just conclusions

## Efficiency Rules

- Prefer cheap local agents before strong/slow agents
- Prefer strong local agents before Claude
- Require verification before promotion of high-value claims
- Cap chaining fan-out so the system does not explode into combinatorial work
- Run behavior verification cheaply and frequently

## Claude Escalation Rules Draft

- Escalate to Claude when:
  - a candidate finding depends on subtle authorization or business-logic interpretation
  - multiple local models disagree materially
  - the system is about to mark a finding as high-confidence/high-severity
  - the chain requires long-horizon reasoning across many artifacts
  - a target-specific workflow keeps failing to converge after repeated bounded attempts
  - a final writeup or exploit reasoning needs stronger judgment
- Do not escalate for:
  - routine summarization
  - endpoint clustering
  - repetitive script generation
  - low-value noise triage

## Claude Augmentation Direction

- Claude should serve three roles:
  - `rescue`
    - when local models are clearly stuck or repeatedly failing to converge
  - `exploit synthesis`
    - when stronger reasoning is needed to propose or refine exploit logic on top of existing tooling
  - `teacher/reviewer`
    - when the system should distill Claude’s stronger reasoning back into reusable notes, patterns, or primitive improvements

- The goal is not to replace local models with Claude for everything
- The goal is to use local models for broad cheap labor and let Claude handle sparse high-value cognition

## Rescue Detection Rules Draft

- A worker should be considered `stuck` when one or more bounded signals fire, not just when output “feels bad”

- Primary stuck signals:
  - repeated bounded attempts fail to improve confidence or evidence quality
  - the worker proposes the same next action repeatedly
  - retries exceed the phase/task threshold
  - local models materially disagree for too long without convergence
  - the worker cannot generate a valid next verification step
  - the worker produces conclusions with low evidence support and high uncertainty
  - exploit generation attempts keep failing static or runtime checks
  - the worker times out or oscillates between conflicting hypotheses

- Secondary stuck signals:
  - no new evidence is produced across multiple task iterations
  - the same blocker appears across multiple related tasks
  - behavior verifier detects loops, duplication, or unsupported claim inflation
  - cost/latency rises without corresponding progress

- Rescue should usually require:
  - a threshold score or a combination of signals
  - not just one noisy failure

## Claude Escalation Flow Draft

- `1. Trigger`
  - orchestrator, verifier, or chaining worker raises an escalation candidate
  - candidate must include:
    - reason for escalation
    - expected value
    - estimated cost tier
    - evidence references
    - current local-model disagreement or uncertainty

- `2. Policy and budget gate`
  - check:
    - target/profile policy
    - approval requirements
    - daily/session spend budget
    - cooldown/deduplication against similar recent escalations
  - reject if the question can be answered cheaply and locally

- `3. Escalation package build`
  - construct a compact bundle, not a raw transcript
  - package should include:
    - task summary
    - target/scope context
    - current hypothesis or exact question
    - relevant evidence summaries
    - only the raw artifacts strictly needed
    - explicit expected output type

- `4. Escalation mode selection`
  - choose one:
    - reasoning review
    - stuck-task rescue
    - exploit synthesis
    - chain review
    - finding review
    - writeup review
    - dispute resolution between local models

- `5. Claude response handling`
  - Claude should return:
    - conclusion
    - confidence
    - reasoning summary
    - evidence gaps
    - next verification actions
    - explicit uncertainty where applicable

- `6. Post-response verification`
  - do not promote Claude output directly to durable truth
  - write it back as:
    - reviewed note
    - finding candidate update
    - verification tasks
    - confidence delta
  - high-impact claims should still pass verification tasks or human review

- `6a. Teach-back path`
  - when Claude materially improves the result, distill the useful parts into:
    - reusable note patterns
    - exploit-generation templates
    - primitive improvement ideas
    - retrieval hints for future similar tasks
  - this is how the local-first system becomes better over time without pretending the local models are suddenly as strong as Claude

- `7. Memory and notification write-back`
  - store escalation request/response metadata
  - link response to task, evidence, and resulting follow-up actions
  - optionally notify operator when the escalation materially changes priority, confidence, or severity

## Automatic Memory Compaction Rules Draft

- Compact immediately after:
  - task completion
  - large tool output ingestion
  - replay/result ingestion from Caido
  - scanner batch completion

- Compact on threshold when:
  - working context exceeds `60-70%` of target prompt budget
  - notes for one target exceed a configured count/size threshold
  - duplicate interest density rises above threshold
  - the same evidence is referenced repeatedly across tasks

- Compact on schedule:
  - light compaction every `5-15` minutes during active runs
  - heavier reconciliation every `1-3` hours
  - daily semantic cleanup for long-lived engagements

## Memory Promotion Rules Draft

- Promote to durable memory only if:
  - evidence-linked
  - seen more than once or verified by a strong primitive
  - tagged with confidence and freshness
  - scoped to a target/program/context

- Keep in working memory only if:
  - actively relevant to the current task window
  - unresolved but likely useful soon

- Demote or expire if:
  - stale without reconfirmation
  - contradicted by new evidence
  - repeatedly unused

## Hardware Constraints

- CPU: AMD 9950X
- RAM: 92GB DDR5
- SSD: Samsung 9100 PRO NVMe PCIe 5.0 x4
- GPU: NVIDIA RTX 5070 with 12GB VRAM

## Storage Implications

- The fast NVMe makes the following design choices more attractive:
  - append-heavy event logging
  - frequent checkpoints
  - large artifact retention
  - vector index maintenance
  - memory snapshotting and rebuild jobs
  - aggressive cache usage for replays, evidence, and retrieval layers

- Design implication:
  - prefer durable, replayable state over fragile in-memory-only execution

## Storage Map Direction

- `Primary live store`
  - `PostgreSQL`
  - Use for canonical operational state:
    - targets
    - scope assets
    - tasks
    - task runs
    - evidence metadata
    - notes
    - interests
    - findings
    - memory entries
    - policy decisions
    - notifications
    - external sync state

- `Vector / retrieval store`
  - `PostgreSQL + pgvector`
  - Use for embeddings tied to notes, evidence summaries, findings, and memory entries
  - Keep vectors close to canonical relational records unless scale later forces separation

- `Artifact store`
  - `filesystem on NVMe`
  - Use for:
    - raw request/response captures
    - Caido exports
    - screenshots
    - scanner raw output
    - exploit POCs
    - logs too large for row storage
    - snapshots/checkpoints
  - Store metadata and references in SQL, not giant blobs inline by default

- `Analytics / archive layer`
  - `Parquet files + DuckDB`
  - Use for:
    - cold historical event logs
    - analytics snapshots
    - large batch exports
    - offline reporting
    - long-horizon trend analysis

- `Where SQLite fits`
  - useful for:
    - portable exports
    - local debug bundles
    - single-file case packages
    - maybe lightweight caches
  - not recommended as the primary live multi-worker control-plane database for this project

## Research Snapshot

- Policy / action control:
  - durable unattended agents should use an explicit policy engine rather than prompt-only restrictions
  - likely candidates: `OPA` or `Cedar`

- Memory / context:
  - research strongly favors hierarchical memory and structured retrieval over giant prompts
  - relevant systems and papers:
    - `MemGPT / Letta`
    - `A-MEM`
    - `SimpleMem`

- Contradiction handling:
  - edited or remembered facts need explicit contradiction checks and external memory references
  - relevant benchmark/method:
    - `MQUAKE / MeLLo`

- Orchestration / durability:
  - long-running agents should use durable workflows, replay, and resumability
  - relevant implementations:
    - `Temporal`
    - `Conductor`
    - `LangGraph`

- Observability / verification:
  - agent verification should rely on traces plus deterministic checks, not only another LLM
  - relevant implementations:
    - `agentevals`
    - `OpenLIT`
    - `OpenLLMetry`
    - `traceAI`

- Planning limits:
  - papers continue to show that LLM planning/reasoning is useful but unreliable without structure
  - relevant papers:
    - `ReAct`
    - `PlanBench`

- Cyber multi-agent relevance:
  - specialist-agent decomposition does help in security settings when planning and exploitation are separated
  - relevant paper:
    - `Teams of LLM Agents can Exploit Zero-Day Vulnerabilities`

## Architecture Corrections

- The project should treat `memory + policy + observability` as core product systems, not support features
- Required architecture corrections based on research:
  - add a deterministic action-policy engine
  - add a durable workflow/runtime layer with replay and resumability
  - add a first-class memory service with contradiction and invalidation support
  - add trace-based agent observability and deterministic behavior checks
  - add model scheduling/arbitration for the single-GPU hot path

- Non-negotiable invariants:
  - no risky action without explicit policy evaluation
  - no durable fact without evidence, provenance, confidence, and freshness
  - no exploit chain accepted without bounded verification tasks succeeding
  - no agent receives full history by default
  - no long-running branch without checkpoints and replayable state
  - no high-confidence claim without traceable support

## Current Architecture Sketch

- `Operator layer`
  - TUI/CLI
  - scope import
  - methodology selection
  - approvals, overrides, review

- `Control plane`
  - durable workflow orchestrator
  - task queue
  - policy engine
  - model scheduler/router

- `Worker plane`
  - recon worker
  - hypothesis / analysis worker
  - exploitation worker
  - chaining worker
  - memory worker
  - behavior-verifier worker

- `Knowledge plane`
  - evidence store
  - note store
  - interest store
  - memory service
  - vector/retrieval index
  - Notion sync/export layer

- `Execution plane`
  - primitive registry
  - primitive executor
  - tool catalog
  - wrapper/adapter layer
  - execution runner / sandbox profile layer
  - output normalization and evidence adapters
  - Caido integration
  - external scanners/scripts/adapters

- `Observability plane`
  - event log
  - trace store
  - cost/latency metrics
  - recovery/failure tracking
  - Discord notification layer

## Tooling Note

- `primitives`
  - This is the correct core term for the tool-execution abstraction
  - External tools/scripts should be wrapped as typed primitives instead of exposed directly to the model
  - The model should reason about capabilities and primitive metadata, not arbitrary shell commands or binary names

## Minimal V1 Stack Direction

- TUI frontend for operator control
- durable orchestrator/workflow runtime
- deterministic policy engine
- structured task/evidence/memory stores
- local model router with hot-path/cold-path separation
- manifest-driven tool catalog and primitive registry
- Caido connector as core web-testing backend
- trace and metrics layer from day one

## Implementation Language Recommendation

- Primary language: `Python 3.12+`
- Reason:
  - strongest fit for AI orchestration, retrieval, local-model integration, and memory tooling
  - best TUI fit via `Textual`
  - good durable workflow support via `Temporal Python SDK`
  - rapid iteration for policy adapters, tracing, and structured memory layers
- Important boundary:
  - if Caido-native plugin or SDK surfaces are easier in JavaScript/TypeScript, keep that as a narrow adapter/plugin boundary rather than making the whole system TypeScript-first

## Tooling Architecture Direction

- The system should assume there will be many heterogeneous tools and scripts
- The model should not see “all tools”; it should see normalized capabilities and approved primitives
- Required tooling concepts:
  - tool manifest
  - primitive wrapper
  - capability taxonomy
  - risk tier
  - side-effect classification
  - auth/secret requirements
  - install/health status
  - output normalizer
  - evidence adapter
  - sandbox/container profile

- The platform should support:
  - onboarding existing scripts without rewriting all of them
  - grouping tools into bundles/profiles by methodology or target type
  - routing by capability rather than raw tool name
  - deterministic post-processing of noisy outputs
  - tool-specific caching, retries, and health checks

## Deployment Direction

- Recommended deployment model: `hybrid`
- Good container candidates:
  - Postgres
  - workflow/control-plane services
  - Notion/Discord sync services
  - many normal workers
  - some model-serving components if desired

- Good host-native candidates:
  - tools that need awkward host networking
  - tools that need privileged access, packet capture, or unusual kernel/device access
  - anything that becomes brittle inside container GPU/network setups
  - possibly Caido, depending on operational preference

- Summary judgment:
  - running the whole system in containers is not a bad idea
  - forcing every worker and every cyber tool into containers is a bad idea
  - the project should support both containerized workers and host-executed primitives

## Notes and Notification Direction

- `Notion`
  - Use Notion as the operator-facing workspace for readable notes and target organization
  - Model-generated notes should be synced into a structured Notion subtree
  - Each HackerOne target or HTB target should get its own target page/folder-like subtree
  - Suggested layout:
    - workspace root
    - program/target page
    - child pages or databases for:
      - overview
      - findings
      - notes
      - evidence links
      - open hypotheses
      - next actions
  - Important constraint:
    - Notion is a presentation and collaboration surface, not the source of truth
    - local structured storage should remain canonical

- `Discord`
  - Use Discord for high-signal notifications only
  - Good notification cases:
    - likely report-worthy finding candidate
    - major confidence/severity change
    - Claude escalation result that materially changes direction
    - long-running workflow failure or repeated recovery failure
    - operator approval needed
  - Avoid notifying for:
    - routine recon noise
    - normal compaction jobs
    - low-value triage churn

## Feasibility Assessment So Far

- Continuous orchestrated operation: feasible
- Local-first stack: feasible
- Fully autonomous all-local top-tier bug hunting: limited by model quality more than infrastructure
- Days-long runtime: feasible if built as a queue/job/checkpoint system, not a persistent chat loop

## Project Assessment Snapshot

- Overall idea quality: strong
- Overall technical feasibility: high for a control-plane-first operator system
- Difficulty: high
- Best realistic near-term outcome:
  - a durable semi-autonomous security workflow platform that excels at recon, triage, evidence management, note/context handling, and bounded verification
- Hardest part:
  - making the system trustworthy over long runtimes while integrating many tools and avoiding context decay
- Lowest-probability outcome:
  - a mostly unattended local-first agent that consistently finds subtle high-value authz/business-logic bugs at top-tier bounty quality

- Rough odds by scope:
  - useful v1 operator platform: `75-85%`
  - good continuous recon/triage/verification assistant: `60-75%`
  - reliable multi-day semi-autonomous workflow engine: `55-70%`
  - strong vuln chaining and exploit-path assistant: `40-60%`
  - mostly autonomous bounty-grade bug hunter as originally imagined: `20-35%`
  - all-local replacement for top premium reasoning models: `10-20%`

## Cost Estimate Snapshot

- For automation, API pricing is the meaningful comparison, not Claude Max chat-plan pricing
- Current official Anthropic API pricing referenced in planning:
  - `Claude Sonnet 4`: `$3 / MTok` input, `$15 / MTok` output
  - `Claude Opus 4.1`: `$15 / MTok` input, `$75 / MTok` output
  - prompt-cache reads are much cheaper, but output pricing still dominates hard reasoning workloads

- Rough savings expectation from the local-first + selective-Claude design:
  - Claude token reduction: roughly `80-95%`
  - Claude cost reduction vs all-Claude Sonnet: roughly `70-90%`
  - Claude cost reduction vs all-Claude Opus: roughly `85-95%`

- Main reason:
  - the high-volume routine work stays local
  - Claude is reserved for sparse, high-value reasoning and exploit synthesis

## ROI Snapshot

- `For a solo operator / bounty hunter`
  - ROI is `moderate`, not immediate
  - Strongest payoff comes from:
    - time saved on recon, triage, note management, and evidence organization
    - better continuity across long-running targets
    - reduced premium-model spend
  - Weakest payoff comes from:
    - expecting the system to independently discover elite-tier bugs right away

- `For internal security / repeated engagements`
  - ROI is `high`
  - Reuse across targets, methodologies, primitives, and note flows compounds strongly

- `For a product/company play`
  - ROI is `potentially high` if the moat is the control plane, tooling substrate, and memory system
  - ROI is `poor` if the pitch is just “multi-agent hacker with local models”

- `Overall ROI judgment`
  - good investment if you target a durable operator platform
  - questionable investment if you target a mostly autonomous bounty machine first

## Execution Confidence Snapshot

- I can help build this project end-to-end in phases
- I do not think the entire ambitious vision should be treated as a one-pass build
- High confidence areas:
  - control plane
  - TUI scaffolding
  - storage layer
  - tooling substrate design
  - memory/evidence schemas
  - Notion/Discord integration
  - Claude augmentation paths
- Lower confidence / higher-risk areas:
  - trustworthy long-horizon autonomous vuln reasoning
  - elite exploit generation quality from local-first flows
  - getting many security tools to behave uniformly without iterative hardening
- Best execution strategy:
  - build a narrow but real v1 first
  - validate each layer
  - add specialist agent behavior only after the control plane is stable

## Build Budget Snapshot

- `800 credits` is likely enough for a disciplined narrow v1
- `800 credits` is not enough for the full ambitious platform with broad tooling coverage and polished autonomy
- `1400 credits` is enough for a strong v1 plus selective v1.5 features
- `1400 credits` is still not enough for the full broad vision with mature autonomy and wide tool coverage

- Likely feasible within `800 credits`:
  - repo scaffolding
  - core Python architecture
  - TUI skeleton
  - storage layer
  - primitive registry/manifests
  - one execution lane
  - basic memory/evidence flow
  - Claude escalation hooks
  - Notion/Discord integration basics
  - one or two real worker paths

- Likely not feasible within `800 credits`:
  - large-scale tool onboarding
  - polished exploit generation flows
  - mature vuln chaining
  - broad operational hardening
  - highly tuned retrieval/memory quality
  - extensive testing across many target/tool profiles

- Likely feasible within `1400 credits`:
  - a solid operator-platform v1
  - multiple real worker paths
  - a better primitive/tooling substrate
  - stronger Claude rescue/exploit-synthesis integration
  - initial Notion/Discord polish
  - limited chaining support
  - better testing and operational cleanup

## Model Capability Reality Check

- The recommended local models are smart enough for:
  - orchestration
  - tool routing
  - note management
  - context compaction
  - hypothesis generation
  - routine code/script synthesis
  - noisy triage and clustering
- They are not smart enough to be blindly trusted for:
  - subtle authz/business-logic vulnerability judgment
  - high-confidence exploitability conclusions
  - complex multi-step target-specific reasoning with sparse evidence
  - final severity or report-quality writeups without review
- Likely shortcomings:
  - false positives from overconfident pattern matching
  - false negatives on nuanced bugs
  - degraded prioritization over long horizons
  - occasional poor tool choice or looping
  - brittle reasoning when context retrieval is weak
  - hallucinated chains if given too much unstructured evidence
- Design implication:
  - local models should operate as planning and analysis workers inside a constrained system
  - premium models such as Claude should remain available for escalation on hard tasks

## Important Constraints and Principles

- Respect explicit scope and program rules
- Separate operating profiles for HackerOne and Hack The Box
- Keep context structured rather than purely narrative
- Store evidence references, IDs, artifacts, and summaries instead of carrying large raw prompts forward
- AI note management must include compaction, dedupe, tagging, and confidence tracking

## External Systems Mentioned

- Caido Client SDK / skills / AI endpoints
- HackerOne scope definitions and files
- Claude agents
- Local model serving
- Notion
- Discord

## Open Questions

- What exact target workflows should be supported in v1?
- What is the preferred language and stack for the TUI?
- How should Claude-agent support be invoked: per task, per workflow, or as an alternate orchestrator/provider?
- How should “interests” be modeled and promoted/demoted over time?
- What primitives are required for the first implementation?
- What are the exact policy boundaries for automation vs. human approval?
- What note/context UX should exist in the TUI?

## Immediate Next Planning Topics

- Data model for interests, notes, primitives, evidence, tasks, and findings
- TUI layout and navigation
- Context lifecycle and compaction pipeline
- Methodology engine design
- Claude/local model provider abstraction
- Reliability plan for multi-day runs
- Model routing and memory/learning pipeline
