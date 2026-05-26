from __future__ import annotations

import unittest

from primordial.core.context import ContextAssembler, ContextEnvelope


class MethodologyAdvisorContextTests(unittest.TestCase):
    def test_methodology_advisor_omits_closed_book_and_sensitive_material(self) -> None:
        def envelope(
            ref: str,
            kind: str,
            source_type: str,
            content: str,
            metadata: dict[str, object] | None = None,
        ) -> ContextEnvelope:
            return ContextEnvelope(
                ref=ref,
                kind=kind,
                authority="advisory" if kind == "rag" else "observed",
                source_type=source_type,
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="methodology_hint",
                sink="prompt",
                content=content,
                citations=[ref],
                metadata=metadata or {},
            )

        envelopes = [
            envelope("evidence:banner", "evidence", "tool_output", "Observed service banner."),
            envelope("rag:vuln-method", "rag", "vuln_intel", "Generic advisory CVE precondition guidance."),
            envelope(
                "rag:closed-book-writeup",
                "rag",
                "writeup",
                "Target-specific writeup reveals the exact path.",
                {"benchmark_mode": "closed_book"},
            ),
            envelope(
                "rag:hidden-solution",
                "rag",
                "ctf_manifest",
                "Hidden benchmark solution text.",
                {"hidden_solution_material": True},
            ),
            envelope(
                "note:credential",
                "operator_note",
                "manual_artifact",
                "Raw credential-bearing note.",
                {"contains_credential": True},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="methodology_hint",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual([item["ref"] for item in packet["sections"]["OBSERVED_EVIDENCE"]], ["evidence:banner"])
        self.assertEqual([item["ref"] for item in packet["sections"]["RAG_ADVISORY"]], ["rag:vuln-method"])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:closed-book-writeup"], "closed_book_forbidden")
        self.assertEqual(omitted_refs["rag:hidden-solution"], "sensitive_material")
        self.assertEqual(omitted_refs["note:credential"], "sensitive_material")
        self.assertNotIn("exact path", packet["rendered"])
        self.assertNotIn("Hidden benchmark", packet["rendered"])
        self.assertNotIn("Raw credential", packet["rendered"])

    def test_methodology_advisor_omits_postmortem_only_writeups_outside_postmortem_scope(self) -> None:
        envelopes = [
            ContextEnvelope(
                ref="rag:active-postmortem-only-writeup",
                kind="rag",
                authority="advisory",
                source_type="writeup",
                target_id="target-a",
                active_generation_id="generation:2",
                purpose="methodology_hint",
                sink="prompt",
                content="Postmortem-only writeup content must not enter active methodology prompts.",
                citations=["rag:active-postmortem-only-writeup"],
                metadata={"writeup_access_policy": "postmortem_only"},
            ),
        ]

        packet = ContextAssembler().assemble(
            envelopes,
            purpose="methodology_hint",
            role="methodology_advisor",
            target_id="target-a",
            active_generation_id="generation:2",
        )

        self.assertEqual(packet["sections"]["RAG_ADVISORY"], [])
        omitted_refs = {item["ref"]: item["reason"] for item in packet["omitted"]}
        self.assertEqual(omitted_refs["rag:active-postmortem-only-writeup"], "postmortem_only_forbidden")
        self.assertNotIn("Postmortem-only writeup content", packet["rendered"])


if __name__ == "__main__":
    unittest.main()
