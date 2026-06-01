---
origin: source_markdown
migration_ref: catalog/policies/agent_runtime.yaml
ingest_allowed: false
operational_retrieval_allowed: false
---

# Primordial Agent Notes

Primordial is a control-plane-first runtime for authorized security work. Treat durable runtime state, evidence records, target scope, approvals, and active Operator Intent as the source of truth.

Default Operator Intent is `recon_only`. Do not assume a scope profile such as `hack_the_box` authorizes public PoC research, Kerberos attack checks, credential validation, or lab flag collection. Those behaviors require the active session intent to allow them.

Keep chat and guidance separate. Chat is conversational context; per-target guidance is durable operator instruction; Operator Intent is the durable control surface that gates task planning and execution.

No public PoC execution, exploit-code generation, brute force, spraying, hash cracking, reverse shell behavior, `shell=True`, automatic tool installation, or unbounded command execution belongs in baseline autonomy.
