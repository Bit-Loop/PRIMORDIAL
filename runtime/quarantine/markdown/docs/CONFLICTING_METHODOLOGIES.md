---
origin: source_markdown
migration_ref: catalog/policies/markdown_migrations.yaml
ingest_allowed: false
operational_retrieval_allowed: false
---

# Conflicting Methodologies And Decision Pressure Map

This document records the main competing ideas inside Primordial. It is meant to make tradeoffs explicit before they become accidental architecture.

Use it as a decision companion when a change could pull the project in two reasonable directions. Each entry names the conflict, gives two contrasting "why" snippets, explains why the idea matters in the larger system, and suggests a practical resolution.

## Reading Frame

Primordial is not just a chatbot, UI, scanner wrapper, or task queue. It is a control-plane-first runtime for authorized security work. That creates persistent tension between safety and speed, structure and flexibility, durable state and transient operator thought.

The right answer is rarely "always pick one side." The better pattern is to decide which layer owns the behavior and make the tradeoff explicit.

## Summary Table

| Conflict | Side A | Side B | Default Resolution |
| --- | --- | --- | --- |
| Source of truth | Durable control plane | Conversational speed | Durable state wins for behavior; chat remains context |
| Autonomy | `recon_only` by default | Capable security workflow | Intent gates capability escalation |
| Methodology structure | Explicit state machines | Evidence-driven planning | Explicit task/run FSMs, planner remains evidence-derived |
| Modularity | Split services | Preserve known behavior | Extract behind tests, no semantic rewrite |
| Evidence handling | Selected import | Automatic ingestion | Explicit import for external traffic |
| Replay approval | Same-session confirmation | Durable replay approval artifacts | Same-session for raw bytes; durable metadata only |
| Model evaluation | Recommend-only | Auto-mutate model roles | Recommendations first, mutation only by operator action |
| Benchmarking | Exhaustive coverage | Fast iteration | Exhaustive scheduled path, smoke path for development |
| AI reasoning | Proposal engine | Deterministic authority | AI proposes; policy/state decide |
| Local execution | Local-first control | Remote premium review | Local default, explicit remote escalation |
| UI design | Fast integrated panels | Clean domain/API boundaries | UI consumes state, runtime owns logic |
| Runtime artifacts | Inspectable artifacts | Clean repo hygiene | Runtime artifacts outside source control |

## 1. Durable Control Plane vs Conversational Speed

**Source of difference:** operator experience vs safety/auditability.

**Snippet A: "The operator said it in chat; the system should adapt immediately."**

This favors fluid interaction. Security work often moves quickly, and forcing every instruction through durable setup can make the system feel slow or rigid.

**Snippet B: "Chat is not the source of truth; durable runtime state is."**

This protects the control plane. A conversation can be ambiguous, stale, or exploratory. Durable state can be inspected, replayed, tested, and audited.

**Grand-scheme importance**

This is one of the core identity questions for Primordial. If chat becomes the authority, Primordial becomes a prompt-driven assistant with a database attached. If durable state remains the authority, Primordial stays a workflow runtime that can use AI without being governed by every transient sentence.

**Pros of conversational speed**

- Faster target correction and workflow steering.
- More natural operator experience.
- Lower friction for exploratory work.

**Cons of conversational speed**

- Harder to audit why a task was planned.
- Easy to mix old context with current target state.
- Risky when chat implies unsafe capability escalation.

**Pros of durable control-plane truth**

- Clear state lineage for scope, tasks, evidence, approvals, and intent.
- Safer recovery after crashes or long sessions.
- Easier to test and explain.

**Cons of durable control-plane truth**

- More ceremony for simple operator corrections.
- Requires explicit UI/API affordances.
- Can feel slower than a pure chat loop.

**Resolution idea**

Keep chat as an input surface, not an authority. Chat may propose target changes, guidance, or next actions, but runtime state must persist the actual decision. Per-target guidance, active Operator Intent, scope assets, evidence records, and approvals should remain durable and inspectable.

## 2. `recon_only` Default vs Capable Security Runtime

**Source of difference:** safety default vs useful authorized-security capability.

**Snippet A: "Default generic sessions to `recon_only`; make HTB lab authorization explicit."**

This is the safety-first posture for generic or bug-bounty targets. The current HTB exception is explicit rather than implicit: the built-in `hack_the_box` profile defaults the session to the `htb_lab` Operator Intent, and the UI surfaces those flags.

**Snippet B: "A security runtime that cannot advance beyond recon is not operationally useful."**

This is the capability pressure. Authorized lab work needs exploitation-adjacent checks, credential validation, and chained reasoning when the operator intends it.

**Grand-scheme importance**

Primordial's long-term value is controlled capability, not blanket refusal. The system needs to perform useful security work while proving that capability is gated by explicit intent, scope, evidence, and approval.

**Pros of `recon_only` default**

- Fails closed.
- Protects against accidental unsafe work.
- Keeps baseline autonomy simple and defensible.

**Cons of `recon_only` default**

- Can block legitimate lab workflows until intent is configured.
- May frustrate users who expect profile-specific behavior.
- Requires clear UI surfacing for "why blocked."

**Pros of richer capability**

- Supports actual end-to-end workflows.
- Makes HTB/lab mode useful.
- Enables evidence-backed progression through methodology phases.

**Cons of richer capability**

- Higher safety and policy burden.
- More edge cases around credentials, PoCs, and replay actions.
- More tests required for gating behavior.

**Resolution idea**

Keep `recon_only` as the generic durable default. For built-in HTB scopes, default the active Operator Intent to `htb_lab` so lab workflows are useful immediately, while still routing stronger behavior through active intent, scope, evidence, approval, and task policy checks. The UI should explain blocked work in terms of the missing intent or missing evidence, not silently skip or imply the task was impossible.

## 3. Explicit State Machines vs Evidence-Driven Methodology Planning

**Source of difference:** formal state correctness vs adaptive planning.

**Snippet A: "Make task/session/methodology state machines explicit with tables."**

This reduces hidden transitions. It helps catch invalid state moves and makes recovery behavior easier to reason about.

**Snippet B: "Methodology is not a pure FSM; it is a planner snapshot derived from evidence."**

This protects flexibility. Planning depends on current-generation evidence, active tasks, blockers, verified interests, operator intent, credentials, and primitives.

**Grand-scheme importance**

This determines whether Primordial evolves like a deterministic workflow engine or like a rule-based reasoning planner. Both are useful, but they should not be confused.

**Pros of explicit state machines**

- Invalid transitions become testable.
- Easier recovery semantics.
- Better audit trail for task/run status changes.

**Cons of explicit state machines**

- Can overfit methodology into a rigid graph.
- Risk of rewriting planner behavior accidentally.
- Transition tables can become fake clarity if guards still live elsewhere.

**Pros of evidence-driven planning**

- Responds naturally to new evidence and target generation changes.
- Avoids hardcoded linear methodology paths.
- Handles blockers and no-progress states better.

**Cons of evidence-driven planning**

- Harder to predict all paths.
- Guard logic can sprawl.
- Complex behavior hides inside helper methods.

**Resolution idea**

Make `TaskStatus`, `TaskRunStatus`, and `SessionStatus` explicit first. Treat methodology state as a derived planning model, not a pure transition table. Add a planner decision record or explanation payload rather than forcing every methodology move into a fixed graph.

## 4. Modular Services vs Behavior Preservation

**Source of difference:** maintainability pressure vs regression risk.

**Snippet A: "Split the large orchestration files now; they are carrying too much."**

This is the maintainability argument. Large files like runtime, workflow, execution, storage, and web API concentrate too many responsibilities.

**Snippet B: "Those files encode working behavior; a broad split can silently change semantics."**

This is the preservation argument. The current coupling is not random; it reflects real state, policy, persistence, event, and execution interactions.

**Grand-scheme importance**

The project cannot scale if every feature lands in the same few hotspots. But the project also cannot afford an architecture cleanup that changes runtime behavior without proof.

**Pros of modular services**

- Smaller files with clearer ownership.
- Easier tests for planner guards, persistence, and policy.
- Lower cognitive load for future contributors.

**Cons of modular services**

- Requires careful dependency boundaries.
- May add indirection before behavior is fully understood.
- Can split code physically while leaving coupling unchanged.

**Pros of preserving current shape**

- Lower immediate risk.
- Existing tests and call paths remain stable.
- Faster small feature work.

**Cons of preserving current shape**

- Complexity compounds.
- Harder review and debugging.
- New features encourage more mixed responsibilities.

**Resolution idea**

Extract by behavior, not by aesthetics. Start with services that can preserve the same inputs and outputs: task status transitions, execution result persistence, planner guard evaluation, and methodology decision explanation. Each extraction should be covered by behavior-preserving tests before additional feature work rides on it.

## 5. Centralized Policy Gates vs Local Feature Logic

**Source of difference:** consistency vs implementation convenience.

**Snippet A: "Put the gate where the feature is built; the local code has all the context."**

This is fast and pragmatic. Feature authors can add checks close to the behavior they are changing.

**Snippet B: "Policy must remain centralized enough to be trusted."**

This keeps safety coherent. If approval and denial rules are scattered, the runtime cannot provide reliable guarantees.

**Grand-scheme importance**

Primordial is only defensible if a reviewer can answer: what actions are allowed, what needs approval, and why? Local feature gates help with context, but central policy gives the system its safety story.

**Pros of local feature logic**

- Faster feature delivery.
- Uses domain-specific context directly.
- Avoids overly generic policy abstractions.

**Cons of local feature logic**

- Duplicated safety checks.
- Harder to audit.
- Higher chance of bypasses between CLI, web, GUI, and worker paths.

**Pros of centralized policy**

- Single explainable admission layer.
- Consistent behavior across surfaces.
- Easier to test against dangerous actions.

**Cons of centralized policy**

- Can become a dumping ground.
- May require richer metadata contracts.
- Might slow down feature iteration.

**Resolution idea**

Keep policy decisions centralized, but let feature code produce structured metadata that policy can evaluate. Local code should describe the action; policy should decide whether it is allowed.

## 6. Selected Evidence Import vs Automatic Ingestion

**Source of difference:** operator curation vs completeness.

**Snippet A: "Search results should stay transient until the operator imports them."**

This prevents noisy or sensitive external data from becoming durable evidence without review.

**Snippet B: "Automatic ingestion captures more context and avoids missed evidence."**

This favors completeness and speed. Operators may forget to import useful traffic, and replay/search workflows benefit from richer historical context.

**Grand-scheme importance**

Evidence is the core currency of Primordial. If the evidence store becomes noisy, stale, or untrusted, planning quality drops. If it is too sparse, the system cannot reason well.

**Pros of selected import**

- Keeps evidence high-signal.
- Preserves operator control.
- Reduces accidental storage of sensitive raw traffic.

**Cons of selected import**

- Requires extra operator action.
- May miss useful context.
- Makes automation less complete.

**Pros of automatic ingestion**

- Better coverage.
- Less manual workflow friction.
- More context for analysis and replay linkage.

**Cons of automatic ingestion**

- Can pollute durable evidence.
- Harder to explain why a task was planned from noisy data.
- Higher storage and redaction burden.

**Resolution idea**

Use transient search by default and selected import for durability. Allow future batch import, but keep it explicit and auditable. Store references, hashes, metadata, and snippets before storing bodies.

## 7. Same-Session Replay Confirmation vs Durable Raw-Request Approval Artifacts

**Source of difference:** safety/audit trail vs secret/raw-data minimization.

**Snippet A: "Replay sends should be confirmed and auditable."**

This supports accountability. A replay action can have security impact and should not be invisible.

**Snippet B: "Do not store raw replay bytes as durable approval artifacts."**

This avoids preserving sensitive material. Raw requests can contain tokens, cookies, credentials, or exploit payloads.

**Grand-scheme importance**

Replay is where Primordial crosses from passive analysis into active HTTP behavior. The system needs operator control without turning raw attack traffic into long-lived sensitive state.

**Pros of durable approval artifacts**

- Strong audit trail.
- Easier review after the fact.
- Can support asynchronous approval workflows.

**Cons of durable approval artifacts**

- Raw request persistence risk.
- Redaction complexity.
- More sensitive data in the database or files.

**Pros of same-session confirmation**

- Lower durable sensitive-data footprint.
- Operator still approves before send.
- Simpler first implementation.

**Cons of same-session confirmation**

- Weaker historical replay of the exact operator decision.
- Harder for asynchronous review.
- Requires UI/session clarity.

**Resolution idea**

Confirm raw replay bytes in-session and durably record metadata only: request id, target, timestamp, intent, result, hashes, and safe snippets. If durable raw approvals are ever needed, gate them behind explicit secure storage and redaction policy.

## 8. Recommend-Only Model Evaluation vs Automatic Model Role Mutation

**Source of difference:** inspectable optimization vs live runtime mutation.

**Snippet A: "Evaluate models and recommend the best roles."**

This supports evidence-based tuning without changing production behavior under the operator.

**Snippet B: "If the benchmark knows the best model, update `model_roles` automatically."**

This maximizes automation. It reduces manual steps and could improve runtime quality quickly.

**Grand-scheme importance**

Model routing affects every AI-assisted decision. Silent role mutation can change behavior across planning, code, reasoning, and compaction. That is a major control-plane event, not a minor setting tweak.

**Pros of recommend-only**

- Operator reviews before changing runtime behavior.
- Produces inspectable CSV/JSON artifacts.
- Easier to compare benchmark runs.

**Cons of recommend-only**

- Requires a manual follow-up.
- Runtime may keep using weaker defaults.
- More CLI/reporting work.

**Pros of automatic mutation**

- Faster adaptation.
- Reduces operator burden.
- Can keep roles fresh as local inventory changes.

**Cons of automatic mutation**

- Surprising behavior changes.
- Harder to debug regressions.
- Benchmark noise can alter live routing.

**Resolution idea**

Default to recommendations and artifacts. Allow an explicit `apply` style action later, with before/after diff, rollback data, and a clear operator confirmation.

## 9. Exhaustive Benchmarking vs Fast Iteration

**Source of difference:** confidence vs feedback speed.

**Snippet A: "Run full exhaustive coverage across local models."**

This gives better role-fit confidence and catches refusal, hallucination, speed, and structured-output differences.

**Snippet B: "Use a fast smoke test so the workflow is practical during development."**

This keeps iteration cheap and prevents long-running evaluations from blocking normal work.

**Grand-scheme importance**

Primordial depends on local models for planning and review quality. The wrong model in the wrong role can degrade safety and usefulness. But a benchmark that is too slow will not be run often.

**Pros of exhaustive evaluation**

- More reliable recommendations.
- Better comparison across Ollama and LM Studio.
- Captures slow/refusal-prone models.

**Cons of exhaustive evaluation**

- Long runtime.
- More resource pressure.
- More complex lifecycle handling for unloaded models.

**Pros of smoke evaluation**

- Fast development feedback.
- Easier CI option.
- Good for checking harness regressions.

**Cons of smoke evaluation**

- Weak role-fit confidence.
- Can miss hallucination or refusal issues.
- Poor basis for model routing changes.

**Resolution idea**

Keep exhaustive as the recommendation default. Add a clearly named smoke mode only for harness development and CI sanity, not for final role recommendations.

## 10. AI Proposals vs Deterministic Authority

**Source of difference:** AI usefulness vs control-plane trust.

**Snippet A: "Let the model propose methodology steps and next actions."**

This captures model reasoning and can uncover useful paths that static rules miss.

**Snippet B: "Do not let AI output become durable truth without deterministic checks."**

This protects the runtime from hallucinated tasks, unsafe capabilities, or stale context.

**Grand-scheme importance**

This conflict defines the role of AI in Primordial. AI should amplify reasoning, not replace policy, evidence, and operator intent.

**Pros of AI proposals**

- More adaptive planning.
- Better use of context and nuance.
- Can surface hypotheses that deterministic rules miss.

**Cons of AI proposals**

- Hallucination risk.
- May invent unsupported primitives.
- Can overreach scope or intent.

**Pros of deterministic authority**

- Testable.
- Auditable.
- Safer under adversarial or ambiguous context.

**Cons of deterministic authority**

- Less adaptive.
- More engineering work to encode useful behavior.
- Can under-plan in novel situations.

**Resolution idea**

AI may propose; deterministic systems admit. Store AI proposals as metadata until primitives, policy, evidence linkage, and intent allow conversion into tasks or durable findings.

## 11. Local-First Execution vs Remote Premium Review

**Source of difference:** privacy/cost/control vs higher-quality external reasoning.

**Snippet A: "Keep execution and reasoning local-first."**

This preserves privacy, cost control, and operator ownership.

**Snippet B: "Some hard analysis deserves premium or remote review."**

This recognizes that local models may miss subtle chains, code issues, or high-value findings.

**Grand-scheme importance**

Primordial's local-first posture is strategically important, but total local isolation can cap reasoning quality. The system needs a principled escalation path.

**Pros of local-first**

- Better privacy.
- Predictable cost.
- Works offline or in lab environments.

**Cons of local-first**

- Model quality limits.
- Slower or weaker hard reasoning.
- More burden on local hardware.

**Pros of remote premium review**

- Better deep reasoning for selected cases.
- Useful for high-value finding review.
- Can reduce false positives.

**Cons of remote premium review**

- Cost and privacy concerns.
- Requires stricter evidence packaging.
- Needs explicit operator approval.

**Resolution idea**

Keep local-first as default. Use remote premium review only through explicit escalation packages, policy checks, and operator-controlled settings.

## 12. Fast UI Feature Growth vs Domain/API Boundaries

**Source of difference:** interface velocity vs maintainable control-plane layering.

**Snippet A: "Add the panel and wire the state directly."**

This is how UI work gets done quickly, especially when the operator needs a control right now.

**Snippet B: "The UI must not invent business logic."**

This preserves the runtime as the authority and prevents CLI/web/GUI drift.

**Grand-scheme importance**

The UI is how operators understand and steer the system. If it diverges from runtime semantics, the operator sees a comforting dashboard rather than the truth.

**Pros of fast UI growth**

- Rapid operator feedback.
- Easier workflow discovery.
- Useful for shaping product direction.

**Cons of fast UI growth**

- Large panels accumulate hidden logic.
- Duplicate behavior across surfaces.
- Harder test coverage.

**Pros of clean boundaries**

- UI renders canonical state.
- Runtime/API contracts stay testable.
- Consistent behavior across CLI, GUI, and web.

**Cons of clean boundaries**

- More upfront API design.
- Slower visual iteration.
- Requires better fixtures and payload contracts.

**Resolution idea**

UI may optimize presentation and interaction, but runtime/API owns state changes and policy-sensitive decisions. If UI needs new behavior, add or clarify a runtime/API contract first.

## 13. Runtime Artifacts In Repo vs Clean Source Hygiene

**Source of difference:** inspectability vs repository clarity.

**Snippet A: "Keep artifacts visible so humans can inspect what happened."**

This makes runs observable and gives the operator concrete outputs.

**Snippet B: "Do not let generated runtime data become source code noise."**

This keeps reviews, scans, and refactors focused on the actual application.

**Grand-scheme importance**

Primordial intentionally produces durable artifacts. But source control should not become the runtime database. Mixing the two makes code review and complexity analysis noisier.

**Pros of visible artifacts**

- Easy inspection.
- Good debugging trail.
- Useful for demos and operator review.

**Cons of visible artifacts**

- Dirty worktrees.
- Accidental sensitive-data commits.
- Distorts complexity and repository health metrics.

**Pros of clean source hygiene**

- Easier review.
- Lower secret/data leakage risk.
- Better automated analysis.

**Cons of clean source hygiene**

- Requires explicit artifact paths and ignore rules.
- Some useful context may be less visible.
- Needs export/import conventions for sharing evidence.

**Resolution idea**

Keep runtime artifacts inspectable but outside tracked source by default. Track only intentional examples, schemas, docs, fixtures, and sanitized test data.

## Cross-Cutting Resolution Principles

1. **Authority belongs to durable state, not prose.**
   Chat, model responses, and notes can influence decisions, but tasks, evidence, approvals, scope, and intent are the operational truth.

2. **AI proposes, deterministic systems admit.**
   Use models for reasoning and prioritization, but require structured primitives, policy checks, and evidence linkage before action.

3. **Safety defaults should fail closed.**
   `recon_only`, selected imports, same-session replay confirmation, and recommend-only model evaluation all follow this pattern.

4. **Escalation must be explicit.**
   Stronger capabilities, remote review, raw replay, credential validation, and model-role mutation should require deliberate operator action.

5. **Refactors should preserve semantics first.**
   Extract services only where tests can prove behavior stayed the same. Use architecture cleanup to reduce future risk, not to smuggle in behavior changes.

6. **Artifacts should be inspectable but intentionally durable.**
   The project benefits from visible evidence and reports, but source control should not absorb live runtime data by accident.

## Practical Decision Template

When a new idea conflicts with an existing method, record:

```text
Idea:
Opposing idea:
Source of difference:
Reason A:
Reason B:
Why this matters long-term:
Pros:
Cons:
Recommended resolution:
What must be tested:
What must not silently change:
```

The goal is not to eliminate disagreement. The goal is to make disagreement operationally useful.
