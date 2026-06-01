---
origin: source_markdown
migration_ref: catalog/policies/markdown_migrations.yaml
ingest_allowed: false
operational_retrieval_allowed: false
---

---
id: caido-httpql
title: Caido HTTPQL Traffic Review
summary: Use Caido as the HTTP traffic source of truth by searching captured requests with narrow HTTPQL filters before promoting web evidence.
tags: caido,httpql,traffic-search,evidence
---

# Caido HTTPQL Traffic Review

Use this skill when a task needs HTTP evidence already captured in Caido.

Core rules:

- Prefer host-scoped HTTPQL filters such as `req.host.eq:"target.htb"` before broader raw-body searches.
- Use response filters such as `resp.code.gte:400` only after the target host or path is constrained.
- Treat Caido request row IDs and replay references as evidence pointers, not as standalone vulnerability proof.
- Do not dump raw request/response bodies into model context unless the receiving worker needs exact bytes.
- Convert Caido results into structured evidence with source references, confidence, freshness, and verification status.

Useful starting filters:

```httpql
req.host.eq:"target.htb"
```

```httpql
req.host.eq:"target.htb" AND resp.code.gte:400
```

```httpql
req.host.eq:"target.htb" AND (req.path.cont:"login" OR req.path.cont:"admin" OR req.path.cont:"api")
```

```httpql
req.host.eq:"target.htb" AND (resp.raw.cont:"api_key" OR resp.raw.cont:"secret" OR resp.raw.cont:"token")
```

Escalation guidance:

- If Caido search returns no results, do not fabricate web evidence. Report that Caido has no matching traffic for the filter and recommend generating scoped traffic through Caido.
- If a result looks interesting, create a follow-up task that references the Caido row/request ID and the exact HTTPQL filter used.
- For HackerOne profiles, keep Caido replay or mutation actions approval-gated unless target policy explicitly allows them.
