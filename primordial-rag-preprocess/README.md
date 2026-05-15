# PRIMORDIAL RAG Preprocess

Local-only preprocessing for a mixed cybersecurity, formal-methods, web-security, Kubernetes, binary-analysis, and ATT&CK corpus.

The pipeline inventories, classifies, policy-gates, extracts, parses, chunks, validates, and writes auditable RAG-ready artifacts. It never modifies source files and never uploads or syncs documents or extracted text.

## Safety And Provenance

- Original files are read-only inputs.
- Unknown commercial or proprietary sources are inventoried and classified, but body extraction is blocked by default.
- Commercial extraction requires an explicit `source_overrides.yaml` entry from the operator.
- Restricted exploit, kernel, binary-analysis, tool-abuse, and post-exploitation-sensitive material is marked `restricted` or `quarantine`.
- Restricted material must not be used in default web/API planning retrieval.
- MITRE ATT&CK JSON is parsed structurally into records; raw ATT&CK bundles are not chunked as giant text blobs.
- Docling is the only document extraction backend. No fallback parsers are used if Docling is missing or fails.
- OCR is disabled by default.

## Install

From the repo root:

```bash
cd primordial-rag-preprocess
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

Docling is required for PDF, EPUB, Markdown, HTML, and text extraction. If Docling is unavailable, the pipeline records an extraction error for that source and continues without fallback extraction.

## Example Run

From `/home/bitloop/Desktop/PRIMORDIAL`:

```bash
python3 primordial-rag-preprocess/scripts/run_pipeline.py \
  --input-dir /home/bitloop/Desktop/PRIMORDIAL/docs/RAG_SRC \
  --output-dir primordial-rag-preprocess/output \
  --policy primordial-rag-preprocess/config/corpus_policy.yaml
```

With commercial-source overrides:

```bash
python3 primordial-rag-preprocess/scripts/run_pipeline.py \
  --input-dir /home/bitloop/Desktop/PRIMORDIAL/docs/RAG_SRC \
  --output-dir primordial-rag-preprocess/output \
  --policy primordial-rag-preprocess/config/corpus_policy.yaml \
  --overrides primordial-rag-preprocess/config/source_overrides.yaml
```

## Phase-Specific Runs

```bash
python3 primordial-rag-preprocess/scripts/run_pipeline.py --input-dir docs/RAG_SRC --inventory-only
python3 primordial-rag-preprocess/scripts/run_pipeline.py --classify-only
python3 primordial-rag-preprocess/scripts/run_pipeline.py --extract-only
python3 primordial-rag-preprocess/scripts/run_pipeline.py --chunk-only
python3 primordial-rag-preprocess/scripts/run_pipeline.py --validate-only
```

The phase scripts under `scripts/` expose the same individual steps for direct debugging.

## Output Structure

```text
output/
  inventory.jsonl
  inventory.csv
  duplicates.json
  classified_sources.jsonl
  classification_report.md
  extracted_sources.jsonl
  extracted/<source_id>.json
  attack/
    enterprise_records.jsonl
    mobile_records.jsonl
    ics_records.jsonl
  chunks/
    chunks.jsonl
    chunks_by_source/<source_id>.jsonl
  indexes/
    attck_enterprise_index.jsonl
    attck_mobile_index.jsonl
    attck_ics_index.jsonl
  validation_report.json
  manifest.json
  manifest.md
```

The output directory is gitignored except for `.gitkeep`.

## Source Metadata

Inventory records include:

- original path and relative path
- file type, byte size, timestamps, SHA-256
- duplicate group and canonical-copy recommendation
- title, author, publisher, and year guesses when available
- source family and provenance flags
- license status, extraction policy, and quarantine reason

Classification records add:

- `authority_level`
- `corpus_type`
- `risk_level`
- `planner_visibility`
- `scope_gate_required`
- `requires_operator_approval`
- `allowed_contexts`

## Chunk Schema

Each chunk includes:

- deterministic `chunk_id`
- `source_id`, `source_sha256`, and `source_path`
- title, author, publisher, year
- page and section location when available
- chunk index and token estimate
- authority, corpus type, domain, risk level
- planner visibility and approval gates
- license status and policy-blocked flag
- extraction warnings
- pipeline version

## Commercial Source Overrides

Copy the example override file and add only hashes the operator has rights to process locally:

```bash
cp primordial-rag-preprocess/config/source_overrides.example.yaml \
   primordial-rag-preprocess/config/source_overrides.yaml
```

Example:

```yaml
sources:
  "sha256_here":
    license_status: "licensed_for_private_rag"
    extraction_allowed: true
    notes: "Operator confirms rights to process locally."
```

Do not use overrides to bypass access controls, DRM, password protection, or licensing uncertainty.

## ATT&CK JSON

Files named `enterprise-attack.json`, `mobile-attack.json`, and `ics-attack.json` are parsed into structured records with:

- technique ID
- name
- ATT&CK domain
- tactics
- description
- platforms
- data sources
- detection text
- mitigations
- relationships
- revoked/deprecated status
- version and source-modified date

All STIX objects with IDs are preserved as structured records, including relationships, mitigations, identities, data sources, and marking definitions. Technique chunks carry technique metadata; non-technique ATT&CK chunks carry the STIX object type and relationship metadata.

ATT&CK chunks use:

- `planner_visibility: taxonomy_only`
- `authority_level: official_taxonomy`
- `scope_gate_required: true`
- `requires_operator_approval: false`

Use ATT&CK for behavior classification, evidence mapping, reporting vocabulary, and detection/mitigation alignment. Do not use ATT&CK to decide scope, choose aggressive actions, bypass authorization, or plan post-exploitation outside an authorized lab.

## Adding OWASP API Markdown

Place local Markdown files under `docs/RAG_SRC/` or a subfolder such as `docs/RAG_SRC/owasp-api-security-top-10/`. They are classified as official API security material when the filename/path matches OWASP API Security patterns.

Extraction still goes through Docling only.

## Adding Kubernetes Docs

Place local Kubernetes, NSA/CISA, CIS, or vendor docs under `docs/RAG_SRC/`. Official Kubernetes/CISA/NSA/CIS material is normal safe-planning context. Books or practical Kubernetes attack material are classified more conservatively.

## Troubleshooting

- `Docling is required; no fallback extractors are enabled`: install or repair Docling, then rerun extraction.
- `policy_blocked=true`: inspect `policy_block_reason`; add an override only if rights and scope are clear.
- No chunks generated: check whether all sources were blocked, Docling failed, or only inventory/classification phases were run.
- Validation failed: inspect `output/validation_report.json` before ingesting any chunks.
