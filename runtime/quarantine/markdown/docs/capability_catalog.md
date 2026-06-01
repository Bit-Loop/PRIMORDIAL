---
origin: source_markdown
migration_ref: catalog/policies/markdown_migrations.yaml
ingest_allowed: false
operational_retrieval_allowed: false
---

# Capability Catalog

Catalog files under `catalog/` externalize baseline control-plane data:

- `catalog/heuristics/`: service discovery, web discovery, and exploit-research heuristics.
- `catalog/playbooks/`: argv-only playbooks. `argv` never includes the executable name; the resolver prepends the resolved tool path.
- `catalog/capabilities/semantics.yaml`: semantic capabilities, approved tools, safe substitutions, and required intent permissions.
- `catalog/agent_skills/`: structured agent-skill metadata.

YAML catalogs are loaded with strict validation. Unknown fields fail fast. Command rendering uses safe interpolation and rejects unknown variables such as `{{ target.missing }}`.

Execution remains `shell=False`, argv-only, timeout-bounded, and provenance-recording.
