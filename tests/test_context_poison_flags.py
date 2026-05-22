from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope, ContextSinkValidator


class ContextPoisonFlagTests(unittest.TestCase):
    def test_rag_index_rejects_hidden_solution_poison_flags(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:hidden-solution",
            kind="rag",
            authority="advisory",
            source_type="ctf_manifest",
            purpose="ctf_benchmark",
            sink="rag_index",
            content="Hidden solution material must not enter active operational RAG.",
            citations=["rag:hidden-solution"],
            poison_flags=["hidden_solution_material"],
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:hidden-solution"])
        self.assertTrue(any("hidden solution material" in error for error in result.errors))

    def test_report_sink_rejects_raw_flag_poison_flags(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:raw-flag",
            kind="ctfd_ref",
            authority="asserted",
            source_type="ctfd",
            purpose="report_generation",
            sink="report",
            content="Raw flag material must not enter report output.",
            poison_flags=["contains_raw_flag"],
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:raw-flag"])
        self.assertTrue(any("hidden or raw sensitive material" in error for error in result.errors))

    def test_report_sink_rejects_scalar_sensitive_poison_flag(self) -> None:
        envelope = ContextEnvelope(
            ref="note:scalar-secret",
            kind="operator_note",
            authority="asserted",
            source_type="notion",
            purpose="report_generation",
            sink="report",
            content="Scalar poison flags must not let secrets enter report context.",
            citations=["note:scalar-secret"],
            poison_flags="contains_secret",
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["note:scalar-secret"])
        self.assertTrue(any("hidden or raw sensitive material" in error for error in result.errors))

    def test_report_sink_rejects_string_encoded_raw_flag_metadata(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:string-raw-flag",
            kind="ctfd_ref",
            authority="asserted",
            source_type="ctfd",
            purpose="report_generation",
            sink="report",
            content="String-encoded metadata must not let raw flag material enter report output.",
            metadata={"Contains raw flag": "true"},
        )

        result = ContextSinkValidator().validate("report", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:string-raw-flag"])
        self.assertTrue(any("hidden or raw sensitive material" in error for error in result.errors))

    def test_ctf_solver_omits_hidden_solution_poison_flags_from_prompt_context(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:generic-method",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content="Generic web enumeration methodology.",
                citations=["rag:generic-method"],
            ),
            ContextEnvelope(
                ref="rag:hidden-path",
                kind="rag",
                authority="advisory",
                source_type="ctf_manifest",
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content="Hidden exact solve path must not enter the solver prompt.",
                citations=["rag:hidden-path"],
                poison_flags=["hidden_solution_material"],
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="ctf_solver_context",
            role="ctf_solver_orchestrator",
            target_id="lab-target",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:generic-method"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:hidden-path"], "sensitive_material")
        self.assertNotIn("Hidden exact solve path", packet["rendered"])

    def test_ctf_solver_omits_human_readable_metadata_poison_flags(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:generic-method",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content="Generic web enumeration methodology.",
                citations=["rag:generic-method"],
            ),
            ContextEnvelope(
                ref="rag:hidden-metadata-path",
                kind="rag",
                authority="advisory",
                source_type="ctf_manifest",
                target_id="lab-target",
                active_generation_id="generation:2",
                purpose="ctf_solver_context",
                sink="prompt",
                content="Display-name metadata reveals the hidden solve path.",
                citations=["rag:hidden-metadata-path"],
                metadata={"Hidden solution material": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="ctf_solver_context",
            role="ctf_solver_orchestrator",
            target_id="lab-target",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:generic-method"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:hidden-metadata-path"], "sensitive_material")
        self.assertNotIn("hidden solve path", packet["rendered"])

    def test_rag_index_rejects_human_readable_metadata_poison_flags(self) -> None:
        envelope = ContextEnvelope(
            ref="rag:hidden-metadata-solution",
            kind="rag",
            authority="advisory",
            source_type="ctf_manifest",
            purpose="ctf_benchmark",
            sink="rag_index",
            content="Display-name metadata must not let hidden solution material enter RAG.",
            citations=["rag:hidden-metadata-solution"],
            metadata={"Hidden solution material": True},
        )

        result = ContextSinkValidator().validate("rag_index", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:hidden-metadata-solution"])
        self.assertTrue(any("hidden solution material" in error for error in result.errors))

    def test_rag_index_rejects_raw_sensitive_material_flags(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:raw-flag",
                kind="rag",
                authority="advisory",
                source_type="ctf_manifest",
                purpose="ctf_benchmark",
                sink="rag_index",
                content="Raw flag material must not enter active operational RAG.",
                citations=["rag:raw-flag"],
                poison_flags=["contains_raw_flag"],
            ),
            ContextEnvelope(
                ref="rag:display-secret",
                kind="rag",
                authority="advisory",
                source_type="methodology_doc",
                purpose="cleanup",
                sink="rag_index",
                content="Human-readable metadata flags must block raw secrets from RAG.",
                citations=["rag:display-secret"],
                metadata={"Contains secret": "yes"},
            ),
        ]

        result = ContextSinkValidator().validate("rag_index", envelopes)

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["rag:display-secret", "rag:raw-flag"])
        self.assertTrue(any("raw sensitive material" in error for error in result.errors))

    def test_ctfd_registry_rejects_raw_flag_poison_flags(self) -> None:
        envelope = ContextEnvelope(
            ref="ctfd:hidden-flag",
            kind="ctfd_ref",
            authority="asserted",
            source_type="ctfd",
            purpose="ctf_benchmark",
            sink="ctfd_registry",
            content="Challenge metadata projection must not expose hidden flags.",
            poison_flags=["contains_raw_expected_flag"],
            metadata={"record_type": "challenge_metadata"},
        )

        result = ContextSinkValidator().validate("ctfd_registry", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["ctfd:hidden-flag"])
        self.assertTrue(any("hidden or raw flag material" in error for error in result.errors))

    def test_github_ledger_rejects_sensitive_poison_flags_without_redaction(self) -> None:
        envelope = ContextEnvelope(
            ref="github:failure-analysis",
            kind="github_ref",
            authority="asserted",
            source_type="github",
            purpose="patch_planning",
            sink="github_ledger",
            content="Engineering ledger entry must not include unredacted secret material.",
            poison_flags=["contains_secret"],
            metadata={"context_type": "failure_analysis", "redacted": False},
        )

        result = ContextSinkValidator().validate("github_ledger", [envelope])

        self.assertFalse(result.valid)
        self.assertEqual(result.accepted_refs, [])
        self.assertEqual(result.rejected_refs, ["github:failure-analysis"])
        self.assertTrue(any("sensitive target material" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
