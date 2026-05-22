from __future__ import annotations


EVIDENCE_PROOF_KINDS = frozenset({"evidence", "finding"})
TRUTH_LIKE_AUTHORITIES = frozenset({"authoritative", "canonical", "confirmed", "observed", "reviewed"})
COLLABORATION_REFERENCE_KINDS = frozenset({"github_ref", "notion_ref"})
COLLABORATION_SOURCE_TYPES = frozenset({"engineering_context", "github", "github_project_context", "notion"})

RAG_ADVISORY_SOURCE_TYPES = frozenset(
    {
        "ctf_manifest",
        "methodology_doc",
        "validated_external",
        "vuln_intel",
        "writeup",
    }
)

NON_EVIDENCE_SOURCE_TYPES = frozenset(
    {
        "ai_output",
        "chat",
        "ctf_manifest",
        "ctfd",
        "engineering_context",
        "export_archive",
        "failure_analysis",
        "generated_export",
        "github",
        "github_project_context",
        "methodology_doc",
        "notion",
        "parser_failure",
        "patch_history",
        "patch_proposal",
        "regression_failure",
        "test_status",
        "vuln_intel",
        "writeup",
    }
)
