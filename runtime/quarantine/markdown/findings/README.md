---
origin: source_markdown
migration_ref: catalog/policies/markdown_migrations.yaml
ingest_allowed: false
operational_retrieval_allowed: false
---

# Primordial Findings Workspace

This folder is durable operator-facing context. Agents may read bounded summaries from target guidance files, but this folder is not loaded wholesale into model prompts.

- `targets/<target>/guidance.md`: operator guidance for agents.
- `targets/<target>/findings.md`: durable finding notes and manual observations.
- `targets/<target>/evidence.md`: lightweight evidence index generated from local state.
- `notion/<target>/notion-export.md`: local Notion-oriented export mirror.
