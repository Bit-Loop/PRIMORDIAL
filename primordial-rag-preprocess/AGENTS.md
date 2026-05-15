# PRIMORDIAL RAG Preprocess Agent Notes

This project is a local-only preprocessing pipeline. Do not modify original corpus files. Do not upload, sync, transmit, or exfiltrate source documents or extracted text.

Default behavior is conservative: unknown commercial or proprietary sources are inventoried and classified, but body text extraction is blocked unless an operator override explicitly permits local processing.

MITRE ATT&CK JSON is parsed structurally into taxonomy records. Do not vectorize raw ATT&CK bundles as giant chunks.

Document extraction is Docling-only. Do not add fallback extractors that silently use other parsers when Docling is unavailable or fails; mark the source as not extracted and preserve the error in outputs.

Restricted exploit, kernel, binary-analysis, post-exploitation, tool-abuse, and low-authority hacking material must not enter normal planner retrieval by default.
