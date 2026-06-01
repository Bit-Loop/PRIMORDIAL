from __future__ import annotations

from tests.test_context_sinks_common import *


class ContextSinkValidatorTestsPart23(ContextSinkValidatorTestsBase):
    def test_rag_index_rejects_generated_export_path_in_unknown_scalar_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:unknown-key-export-path-advisory",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Generated export paths must not be hidden under arbitrary scalar metadata.",
            citations=["rag:unknown-key-export-path-advisory"],
            metadata={"provenance_url": "https://example.invalid/findings/notion/target-a/notion-export.md"},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:unknown-key-export-path-advisory"])
        self.assertTrue(any("generated export" in error for error in result.errors))

    def test_rag_index_rejects_malformed_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:malformed-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Malformed source refs must not be normalized into supported-looking provenance.",
            citations=["rag:malformed-source-refs"],
            metadata={"source_refs": ["rag:valid-source", 42]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:malformed-source-refs"])
        self.assertTrue(any("malformed source_refs" in error for error in result.errors))

    def test_rag_index_rejects_display_source_reference_alias_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:display-source-reference-alias",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Display source-reference aliases must not bypass provenance checks.",
            citations=["rag:display-source-reference-alias", "github:issue-42"],
            metadata={"Source reference": "github:issue-42"},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:display-source-reference-alias"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_rag_index_rejects_display_source_ref_alias_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:display-source-ref-alias",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Short display source-ref aliases must not bypass provenance checks.",
            citations=["rag:display-source-ref-alias", "github:issue-42"],
            metadata={"Source ref": "github:issue-42"},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:display-source-ref-alias"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_rag_index_rejects_display_source_references_alias_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:display-source-references-alias",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Plural display source-reference aliases must not bypass provenance checks.",
            citations=["rag:display-source-references-alias", "github:issue-42"],
            metadata={"Source references": ["github:issue-42"]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:display-source-references-alias"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_rag_index_rejects_double_nested_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:double-nested-source-refs",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Double-nested source refs must not bypass provenance checks.",
            citations=["rag:double-nested-source-refs", "github:issue-42"],
            metadata={"layers": [[{"source_refs": ["github:issue-42"]}]]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:double-nested-source-refs"])
        self.assertTrue(any("unsupported source_refs" in error for error in result.errors))

    def test_rag_index_rejects_placeholder_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:placeholder-source-ref-owner",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Placeholder source refs must not become active provenance.",
            citations=["rag:placeholder-source-ref-owner"],
            metadata={"source_refs": ["rag:unknown"]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:placeholder-source-ref-owner"])
        self.assertTrue(any("placeholder source_refs" in error for error in result.errors))

    def test_rag_index_rejects_non_rag_placeholder_source_refs_metadata(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:placeholder-evidence-source-ref-owner",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Placeholder evidence refs must not become active provenance.",
                citations=["rag:placeholder-evidence-source-ref-owner", "evidence:unknown"],
                metadata={"source_refs": ["evidence:unknown"]},
            ),
            ContextEnvelope(
                ref="rag:placeholder-note-source-ref-owner",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Placeholder note refs must not become active provenance.",
                citations=["rag:placeholder-note-source-ref-owner", "note:null"],
                metadata={"source_refs": ["note:null"]},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(
            result.rejected_refs,
            ["rag:placeholder-evidence-source-ref-owner", "rag:placeholder-note-source-ref-owner"],
        )
        self.assertTrue(any("placeholder source_refs" in error for error in result.errors))

    def test_rag_index_rejects_uncited_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:uncited-source-ref-owner",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="Source refs must be cited before entering active RAG provenance.",
            citations=["rag:uncited-source-ref-owner"],
            metadata={"source_refs": ["rag:curated-source"]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:uncited-source-ref-owner"])
        self.assertTrue(any("uncited source_refs" in error for error in result.errors))

    def test_rag_index_rejects_unresolved_evidence_source_refs_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:unresolved-evidence-source-ref-owner",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="RAG provenance must not cite evidence that is not in the evidence ledger.",
            citations=["rag:unresolved-evidence-source-ref-owner", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope], known_evidence_refs=set())

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:unresolved-evidence-source-ref-owner"])
        self.assertTrue(any("unresolved evidence citation" in error for error in result.errors))

    def test_rag_index_rejects_source_refs_against_rejected_operator_note(self) -> None:
        note = ContextEnvelope(
            ref="note:bad-rag-index-provenance",
            kind="operator_note",
            authority="asserted",
            source_type="manual_artifact",
            purpose="cleanup",
            sink="rag_index",
            content="Operator note provenance must not cite unresolved evidence before indexing.",
            citations=["note:bad-rag-index-provenance", "evidence:missing-banner"],
            metadata={"source_refs": ["evidence:missing-banner"]},
        )
        envelope = ContextEnvelope(
            ref="rag:bad-note-backed-source-ref",
            kind="rag",
            authority="advisory",
            source_type="methodology_doc",
            purpose="cleanup",
            sink="rag_index",
            content="RAG provenance must not cite operator notes rejected from the same index batch.",
            citations=["rag:bad-note-backed-source-ref", "note:bad-rag-index-provenance"],
            metadata={"source_refs": ["note:bad-rag-index-provenance"]},
        )

        result = ContextSinkValidator().validate("rag_index", [note, envelope], known_evidence_refs=set())

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:bad-rag-index-provenance", "rag:bad-note-backed-source-ref"])
        self.assertTrue(any("unresolved note citation" in error for error in result.errors))

__all__ = ["ContextSinkValidatorTestsPart23"]
