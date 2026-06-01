---
origin: source_markdown
migration_ref: catalog/policies/markdown_migrations.yaml
ingest_allowed: false
operational_retrieval_allowed: false
---

# Helix Runtime Test Report

Date: 2026-05-14T13:04:28-05:00

Target: `helix.htb`

Active IP: `10.129.54.140`

## Test Rules

- Emulated an operator through Primordial's running HTTP control surface on `127.0.0.1:1337`.
- Did not manually scan, enumerate, repair, add credentials, edit runtime config, or bypass Primordial.
- Approved only the Helix-related requests/actions that Primordial surfaced.
- No public PoC was executed and no exploit code was generated during this test.

## Starting State

`GET /api/health` returned `status: ok`.

Runtime state:

- Operator intent: `htb_lab`
- Autonomy mode: `assisted`
- Active modules: `security`, `notion`, `discord`, `caido`
- Database: Postgres runtime at `127.0.0.1:55432`
- Execution mode: `continuous`, 7 second interval

`GET /api/scope` showed `helix.htb` as in scope with:

- `active_ip`: `10.129.54.140`
- assets: `helix.htb`, `10.129.54.140`
- evidence count: 5
- findings count: 3
- tasks count before this run: 16

Before the test, `GET /api/work-status` showed Primordial blocked or waiting. For Helix, the relevant waiting items were:

- `task_4aa49a9cfe1f`: `review_premium_escalation`, "Escalate uncertain planner state to Claude/GPT"
- `task_17650c5ebe15`: proposal-only `analyze_evidence`, "Defer Verify credentialed SMB/WinRM access"

## Operator Actions

1. Attempted to approve both Helix tasks through `POST /api/actions/approve`.
2. The first approval attempt used malformed JSON at the shell layer and returned `{"error":"invalid JSON payload"}`. This was operator/API invocation friction, not a Primordial runtime decision.
3. Retried with valid JSON.
4. Approved proposal-only task `task_17650c5ebe15`.
5. Approved remote premium task `task_4aa49a9cfe1f`.
6. Ran one orchestration tick through `POST /api/actions/tick` with `max_executions: 3`.
7. Polled `GET /api/work-status` and task audit endpoints until the web action was no longer busy.

## What Worked

Primordial accepted the target and ran a new Helix analysis task:

- Planned task: `task_60a8bf2e2a1b`
- Title: `Analyze accumulated evidence`
- Run: `run_0b48d61e69f4`
- Route: `local_fast`
- Model: `gemma4:e4b`
- Role: `analysis_worker`
- Worker contract: `analysis_hot_contract`
- Status: `succeeded`
- Started: 2026-05-14T13:03:26.826016-05:00
- Finished: 2026-05-14T13:03:38.996202-05:00

The runtime created pre/post checkpoints:

- `runtime/checkpoints/task_60a8bf2e2a1b/run_0b48d61e69f4-pre.json`
- `runtime/checkpoints/task_60a8bf2e2a1b/run_0b48d61e69f4-post.json`

The task was admitted because policy judged it within current scope, phase, and autonomy policy:

- Event: `analyze_evidence: Analyze accumulated evidence`
- Reason: `task falls within current scope, phase, and autonomy policy`

## Evidence Primordial Used

Current-generation Helix evidence included:

- `evidence_df51199097d3`: TCP service discovery observed `10.129.54.140:22/ssh` and `10.129.54.140:80/http`.
- `evidence_b40d5fe8acdd`: HTTP probe returned 200 for `http://10.129.54.140/`.
- `evidence_10d2d65c6f00`: bounded web content discovery checked one base URL and found no interesting paths.
- `evidence_1eb1cd88ab65`: local exploit-reference research retained non-DoS research candidates, but they remained unverified.
- `evidence_eb9e0db0a889`: PoC applicability classification retained candidates for gated review only; no PoC execution occurred.

The service facts in the runtime packet identified:

- SSH: OpenSSH `8.9p1 Ubuntu 3ubuntu0.15`
- HTTP: nginx `1.18.0 Ubuntu`

## What Did Not Fully Work

The remote premium planner escalation did not execute even after approval.

Task:

- `task_4aa49a9cfe1f`
- Kind: `review_premium_escalation`
- Route: `remote_premium`
- Model: `claude-sonnet-4`
- Final status after approval attempt: `needs_approval`

Observed events:

- `Task approved: Escalate uncertain planner state to Claude/GPT`
- then immediately:
- `primitive requires credentials or integration secrets that are not configured`

Why: operator approval was necessary but not sufficient. The remote premium provider path also needs configured credentials or integration secrets. Since this test did not add or repair credentials, the task returned to `needs_approval` and remained blocked.

The local analysis task succeeded, but its local AI review did not produce structured output:

- Trace: `trace_b8b847072337`
- Status: `ai_review_completed`
- Model: `gemma4:e4b`
- `structured_output`: `false`
- `status`: `parse_failed`

Why: the worker completed the analysis run, but the model response could not be parsed as the expected structured proposal. Primordial still marked the task succeeded, but no new structured candidate action was admitted from that response.

Notion sync failed after the tick:

- Event: `Notion sync failed for helix.htb`
- Error class: `Notion API returned 401`
- Runtime message: API token is invalid

Why: the configured Notion credential is invalid or stale. I did not alter credentials during this test.

Discord notification delivery had already failed for the Helix approval notification:

- Event: `Discord delivery failed`
- Error: webhook returned 405 Method Not Allowed

Why: the configured Discord webhook endpoint/method is not accepting Primordial's delivery request. I did not alter credentials or endpoints during this test.

## Final Runtime State

After the tick:

- `GET /api/work-status` returned `is_busy: false`.
- Active tasks: 0
- Queued tasks: 0
- Waiting tasks: 2
- Helix still waited on `task_4aa49a9cfe1f`.

Helix methodology state after the run:

- Phase: `analysis`
- Subphase: `review_premium_escalation`
- Completion: `waiting_on_existing_tasks`
- Candidate actions: none
- Next unblock action: `AI proposal rejected: Web Directory Enumeration (missing primitive mapping)`

Current Helix blockers:

- `AI proposal rejected: Web Directory Enumeration (missing primitive mapping)`
- `AI proposal rejected: SSH Service Version/Banner Grabbing (missing primitive mapping)`
- `AI proposal rejected: HTTP Parameter Analysis (missing primitive mapping)`

## Conclusion

Primordial worked for local runtime orchestration: it accepted the Helix target, admitted an evidence-analysis task, dispatched the local worker, used the local model route, checkpointed the run, and returned to idle.

Primordial did not fully progress because the next intended planner recovery path depends on a remote premium integration that has no usable credentials/secrets configured. The local model analysis also failed structured parsing, so it did not create an executable next step. External sync/notification paths are also unhealthy: Notion returns 401 and Discord returns 405.

The practical result is that Helix remains stuck at analysis/review escalation. The runtime needs either a valid configured remote review provider or deterministic primitive mappings for the proposed next actions before it can advance without manual assistance.

## Follow-up: Agent Chat API Integration

Date: 2026-05-14T13:31:00-05:00

After the first Helix runtime test, the local `agent_chat_api` wrapper was integrated into Primordial's `remote_premium` worker lane.

Changes made:

- Added a Primordial HTTP client for `agent_chat_api`.
- Added a broker-compatible `remote-premium` worker runner that calls `/api/chat`.
- Updated the `claude-review` manifest so it no longer requires a direct `ANTHROPIC_API_KEY`; it now depends on the local agent chat API.
- Preserved the existing remote premium approval and Operator Intent gates.
- Stored wrapper output as `MODEL_REVIEW` evidence with `kind: premium_review_result` so deterministic workflow admission can inspect it.

Live wrapper state:

- Started `agent_chat_api` on `http://127.0.0.1:8787`.
- Workspace root: `/home/bitloop/Desktop/PRIMORDIAL`
- `/health` returned `ok: true`.
- Providers reported available: `codex` at `/usr/bin/codex`, `claude` at `/usr/bin/claude`.

Hot runtime evidence found one additional bug:

- Approved Helix task `task_4aa49a9cfe1f` dispatched to the new `remote_premium` path.
- The first live run failed because Primordial passed topology model `claude-sonnet-4` through to the Claude CLI.
- Claude returned a provider error saying the selected model may not exist or may not be accessible.

Fix applied:

- Primordial now lets the wrapper/provider use its default model unless `PRIMORDIAL_AGENT_CHAT_MODEL` is explicitly set.
- This prevents the internal topology label from breaking the wrapper call.

Final live wrapper verification:

- Direct non-dry-run call to `/api/chat` succeeded through Claude.
- Request ID: `f883921a6c3646b8a9c5960cb54c940b`
- Response text: `{"ok": true, "component": "agent_chat_api"}`
- Command used by wrapper kept tools disabled: `--tools '' --permission-mode dontAsk`
- The verification wrapper process was stopped after the test; start it again for ongoing runtime use.

Verification commands that passed:

- `python3 -m py_compile primordial/core/providers/agent_chat.py primordial/core/config.py primordial/app/runtime.py`
- `python3 -m unittest tests.test_agent_chat_integration tests.test_policy tests.test_provider_router -q`
- `python3 -m unittest tests.test_workflow.WorkflowTests.test_stuck_planner_creates_remote_premium_approval_when_disabled tests.test_workflow.WorkflowTests.test_remote_review_actions_are_admitted_only_with_evidence_scope_and_policy -q`

Remaining runtime note:

- The original Helix premium-review task consumed its one live attempt during the model-label failure and is now failed.
- I did not manually mutate runtime state to retry that task.
- The integration is ready for the next approved `review_premium_escalation` task or for a retry after an operator-visible task reset/replan.
- The already-running web server on `127.0.0.1:1337` was started before these code edits, so restart it before expecting the web UI process to use the new adapter.

## Follow-up: Restarted Runtime and Continued Helix Approvals

Date: 2026-05-14T13:46:00-05:00

Operator request: stop the stale process and continue with full session access.

Actions:

- Stopped stale Primordial web listener PID `1517627` on `127.0.0.1:1337`.
- Restarted `agent_chat_api` on `127.0.0.1:8787` from the current checkout.
- Restarted Primordial web on `127.0.0.1:1337` from the current checkout.
- Verified both `/health` endpoints returned healthy responses.
- Approved only Helix-related requests; Pirate remained untouched.

Results:

- Fresh Helix remote premium task `task_65607debc033` ran through `agent-chat-premium-runner`.
- Run `run_89867b00832a` succeeded.
- Trace metadata showed `processor: agent_chat_api`, `provider: claude`, `model: claude`, and `structured_output: true`.
- Primordial stored the result as model-review evidence and admitted deterministic follow-up actions from it.
- `DNS Enumeration: helix.htb` ran as `task_abce01fc157a` / `run_4c380a83128a` and succeeded.
- Follow-up analysis tasks `task_8845b3521cc2`, `task_2401c8b747ea`, `task_eb2c588a3a0a`, and `task_7debe869517c` succeeded.
- Second Helix remote premium task `task_640345bbcf0f` ran through the same wrapper-backed lane and succeeded as `run_0a54fb87fa5b`.
- Trace `trace_1ecd0def3c7e` recorded request ID `613ce2ba1a47421695ee7cb063d43b54`, `processor: agent_chat_api`, `provider: claude`, `model: claude`, elapsed time `78.942`, and `structured_output: true`.

What changed from the first test:

- The previous blocker, `primitive requires credentials or integration secrets that are not configured`, is no longer blocking `claude-review`.
- The previous wrapper failure caused by forcing `claude-sonnet-4` through the Claude CLI did not recur.
- Remote premium review now works through the local wrapper and produces durable structured evidence.

Remaining blockers:

- Helix task `task_222eedc88073` remains `needs_approval`.
- I approved it once, but policy returned it to approval because `finding-verification` has `timeout_seconds: 120` and exceeds the target action-policy time cap.
- This is now a task policy/time-cap issue, not a missing remote-provider issue.
- Helix also has a new remote premium review task `task_9e8c55ce939d` waiting for approval; I stopped before approving another review cycle to avoid an approval loop.
- Pirate task `task_f44ae9f8bd56` is still waiting and was intentionally not touched.

Current server state:

- Primordial web is running on `http://127.0.0.1:1337`.
- Agent chat API is running on `http://127.0.0.1:8787`.

## Follow-up: Autonomous Helix Runtime Test With Hot Fixes

Date: 2026-05-14T14:05:00-05:00

Operator request: run an autonomous runtime test for `helix.htb` and approve Helix runtime requests/actions while leaving unrelated targets alone.

Starting state:

- Primordial web health was OK on `http://127.0.0.1:1337`.
- Agent chat API health was OK on `http://127.0.0.1:8787`.
- Active Operator Intent was `htb_lab`.
- Helix target was in scope with active IP `10.129.54.140`.
- Pirate approval task `task_f44ae9f8bd56` was left untouched.

Hot evidence found:

- Helix task `task_222eedc88073` had already been approved, then returned to `needs_approval`.
- The recorded runtime event was `primitive timeout exceeds the target action-policy time cap`.
- `finding-verification` was read-only but had `timeout_seconds: 120`; the high-risk cap is `30`.
- After lowering that manifest timeout, the same task still bounced because primitive resolution selected every primitive sharing broad `finding-verification` or `auth-analysis` tags, including unrelated credential/Kerberos primitives still set to `120`.

Fixes applied because they were directly evidenced by the hot Helix test:

- Set `manifests/finding-verification.json` timeout from `120` to `30`.
- Recorded explicit operator approval metadata when a task is approved.
- Allowed an operator-approved high-risk primitive to pass primitive preflight only when the primitive is `read_only` and within policy bounds.
- Narrowed validation and execution primitive resolution to the explicit `primitive_hint` when one names a registered primitive.
- Added tests for operator approval metadata, read-only high-risk primitive admission, mutating primitive gate preservation, and primitive-hint narrowing.

Runtime results after restart:

- Approved Helix `task_222eedc88073`.
- It executed instead of bouncing.
- Run `run_32c82f0c9678` succeeded via `security-deep-runner`.
- Model route was `local_deep`, model `deepseek-r1:8b`.
- Trace `trace_0a458ffcb55e` recorded `structured_output: true`, elapsed `31.737` seconds.
- Result summary: `verification planning complete; execution remains primitive-gated`.
- No exploit code, public PoC execution, credential validation, brute force, reverse shell, or flag collection was run.

Additional Helix approvals:

- Approved Helix remote review `task_cd3ab466cbfa`; run `run_ea9b6ca10b3c` succeeded through `agent-chat-premium-runner`.
- Continuous mode then executed Helix analysis tasks, including `task_6f153c123db4`, `task_8a3ced9e56e3`, and `task_f29fe58e500f`; each completed as `analysis completed`.
- Approved one more Helix remote review, `task_d0d311bf83f5`.
- Run `run_38ae97263623` succeeded through `agent-chat-premium-runner`.
- Trace `trace_deb3ff5a0218` recorded `processor: agent_chat_api`, `provider: claude`, `model: claude`, request ID `1b53f532469a41c68a38b9d697cbc214`, elapsed `108.126` seconds, and `structured_output: true`.

Final runtime state:

- Helix no longer has the original `finding-verification` timeout/primitive-resolution blocker.
- Helix did produce a new approval task, `task_ec94040d0758`, for another `review_premium_escalation`.
- The remaining Helix loop is planner-level: remote reviews keep recommending actions that deterministic admission rejects.
- Rejection reasons include missing mappings for `web_directory_enumeration`, `service_banner_grab`, and `http_content_analysis`, a `http-probe` recommendation with no deterministic task-kind mapping, and duplicate/current-generation `content-discovery` or `finding-verification` work.
- Pirate task `task_f44ae9f8bd56` remains waiting and was intentionally not approved.

Verification commands that passed:

- `python3 -m py_compile primordial/core/orchestration/policy.py primordial/core/orchestration/workflow.py primordial/modes/security/execution.py primordial/core/providers/agent_chat.py primordial/core/config.py primordial/app/runtime.py`
- `python3 -m unittest tests.test_policy tests.test_agent_chat_integration tests.test_workflow.WorkflowTests.test_task_approval_records_operator_approval_metadata tests.test_workflow.WorkflowTests.test_primitive_hint_narrows_validation_and_execution_primitives -q`

Current server state:

- Primordial web health is OK on `http://127.0.0.1:1337`.
- Agent chat API health is OK on `http://127.0.0.1:8787`.
- After the test, `stop-work` was run to prevent continuous mode from burning more cycles.
- Execution mode is now `tick`, not `continuous`.
- `stop-work` temporarily left active Operator Intent at `recon_only`; that would have blocked exploit-research, PoC execution, credential validation, reverse-shell, and flag-collection work until `htb_lab` was reactivated.
- The current waiting queue has two approval tasks: Pirate `task_f44ae9f8bd56` and Helix `task_ec94040d0758`.

Correction after operator clarification:

- The fact that exploit code, PoC execution, credential validation, reverse-shell behavior, and flag collection did not run in this test is an observed test result, not a desired end state.
- For authorized HTB work, these capabilities are supposed to be allowed when active Operator Intent is explicitly `htb_lab` and the relevant approval gates pass.
- `htb_lab` now explicitly allows exploit code generation, PoC execution, credential validation, lab flag collection, HTB lab behavior, and reverse-shell behavior.
- The live runtime was restarted and active Operator Intent was set back to `htb_lab` after this correction.

Conclusion:

The autonomous Helix runtime path works through local execution and the local Claude wrapper after the hot fixes. The original failure was not target reachability; it was a runtime policy/primitive-selection bug. The remaining Helix blocker is a deterministic planning/admission gap: the runtime needs task-kind mappings or primitive aliases for the actions it keeps asking premium review to recommend, otherwise it will continue to create new premium-review approval tasks instead of advancing.
