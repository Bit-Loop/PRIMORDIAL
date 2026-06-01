---
origin: source_markdown
migration_ref: catalog/policies/markdown_migrations.yaml
ingest_allowed: false
operational_retrieval_allowed: false
---

# Autonomous Runtime Test Report

Date: 2026-05-14  
Runtime window: approximately 14:17-14:36 US/Central  
Mode tested: Primordial continuous execution with operator approvals only

## Scope

I interacted only with the Primordial control plane API. I approved tasks Primordial requested, polled runtime state, and stopped continuous mode at the end. I did not run target tooling manually, add planner hints, execute PoCs outside Primordial, validate credentials outside Primordial, or edit code during the run.

Targets observed:

- `helix.htb` with confirmed IP `10.129.54.140`
- `pirate.htb`

## Starting State

- Primordial web API was reachable on `127.0.0.1:1337`.
- Agent chat wrapper was already integrated and reachable through Primordial's premium review runner.
- Continuous mode was enabled with a 7 second interval.
- The run had waiting premium-review approvals for Helix and Pirate.

## Approvals Given

Approved tasks during this run:

- `task_ec94040d0758` - Helix premium review, succeeded as `run_8eae3f0af1ab`.
- `task_8620d834a55e` - Pirate premium review, succeeded as `run_8848ac961048`.
- `task_b72ebac7a16c` - Helix premium review, succeeded as `run_7aed2eacfbe4`.
- `task_2178bceb080e` - Pirate premium review, succeeded as `run_bbf7ecf9d9c4`.
- `task_7790189ee50b` - Pirate finding verification, succeeded as `run_55ad149d252c`.
- `task_13afc9e554b2` - Helix premium review, succeeded as `run_d80088d590c8`.
- `task_aebea659ff1c` - Pirate premium review, succeeded as `run_4b68744ad647`.

## What Primordial Did Autonomously

After approvals, Primordial autonomously ran repeated evidence-analysis tasks on both targets. It also advanced Pirate further than Helix:

- Pirate DNS enumeration ran and succeeded: `task_2bb12be4a09a` / `run_5fb4d43e512e`, summary `DNS enumeration completed`.
- Pirate finding verification ran and succeeded: `task_7790189ee50b` / `run_55ad149d252c`, summary `verification planning complete; execution remains primitive-gated`.
- Helix repeatedly completed `analyze_evidence` tasks, then returned to premium-review escalation.

No manual target commands were run by me. No observed Primordial result reached PoC execution, credential validation, reverse-shell behavior, or flag collection during this test window.

## Where It Stopped

The run was stopped manually after Primordial settled back into review gates. Final work status:

- Execution mode: `tick`
- Continuous mode: `false`
- Active tasks: `0`
- Queued tasks: `0`
- Waiting tasks: `2`
- Busy: `false`

Remaining waiting tasks:

- `task_79a1faa1d7fb` - Helix premium review escalation
- `task_052b1858679d` - Pirate premium review escalation

Final target-state blockers reported by Primordial:

- `helix.htb`: `Active operator intent does not allow public PoC applicability validation.`
- `pirate.htb`: `Active operator intent does not allow public PoC applicability validation.`

The live `/api/operator-intent` endpoint at report time showed active intent `recon_only`. The available `htb_lab` intent exists and allows public PoC research, PoC applicability validation, PoC execution, credential validation, reverse-shell behavior, and lab flag collection, but it was not the active runtime intent at the end of this run.

## Result

Primordial got as far as:

1. Premium review escalation through the agent-chat wrapper.
2. Automated evidence-analysis cycles.
3. A deterministic Pirate DNS enumeration task.
4. A gated Pirate finding-verification task using `local_deep`.

It did not progress into PoC execution or later HTB-style actions. The immediate reasons were:

- The live active Operator Intent ended as `recon_only`, which blocked public PoC applicability validation.
- Helix and Pirate both returned to premium-review escalation after analysis.
- Earlier Helix/Pirate planner recommendations still showed missing primitive mappings for common next steps such as HTTP directory enumeration, banner/version probing, HTTP content/header analysis, and targeted SSH version enumeration.

## Notable Runtime Issue

Work status also continued to show an empty target entry (`target: ""`) with bootstrap recon candidates. That looks like stale or malformed target state and should be investigated separately because it can distract the planner from real scoped targets.
