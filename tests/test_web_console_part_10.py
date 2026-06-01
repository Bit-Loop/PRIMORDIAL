from __future__ import annotations

from tests.test_web_console_common import *


class WebConsoleTestsPart10(WebConsoleTestsBase):
    def test_operator_inquiry_infers_target_and_answers_ports_auth_and_escalation_from_state(self) -> None:
        target = self.runtime.register_target(
            handle="example.test",
            profile=ScopeProfile.HACKERONE,
            assets=["example.test", "203.0.113.37"],
            emit_event=False,
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="TCP service discovery: example.test",
                summary="TCP service discovery observed SSH and HTTP.",
                source_ref="fixture://example-services",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.9,
                freshness=0.9,
                metadata={
                    "kind": "tcp_service_discovery",
                    "open_services": [
                        {"host": "203.0.113.37", "port": 22, "service": "ssh"},
                        {"host": "203.0.113.37", "port": 80, "service": "http"},
                    ],
                },
            )
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Recon: http://example.test/",
                summary="HTTP probe returned 200 for http://example.test/ with content-type text/html.",
                source_ref="fixture://example-http",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.85,
                freshness=0.9,
                metadata={
                    "kind": "recon_scan",
                    "effective_url": "http://example.test/",
                    "status_code": 200,
                    "auth_surfaces": [],
                    "forms": [],
                    "paths": ["/"],
                },
            )
        )

        with patch.object(self.runtime.ollama, "generate") as generate:
            response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps(
                    {
                        "message": (
                            "Are there only 2 open ports on example.test? Is there any login portals "
                            "on the site? (port 80) can we escalate this to gpt?"
                        )
                    }
                ).encode("utf-8"),
            )

        payload = json.loads(response.body)
        answer = payload["result"]["chat"]["answer"]["body"]
        review_tasks = [
            task
            for task in self.runtime.store.list_tasks(target_id=target.id, limit=20)
            if task.kind == TaskKind.REVIEW_PREMIUM_ESCALATION
        ]

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["result"]["chat"]["model"], "deterministic-state")
        self.assertIn("2 unique open TCP port", answer)
        self.assertIn("`22/ssh`", answer)
        self.assertIn("`80/http`", answer)
        self.assertIn("not proof that no other ports exist", answer)
        self.assertIn("No stored current evidence identifies a login portal on port 80", answer)
        self.assertIn("**Premium Review**", answer)
        self.assertEqual(len(review_tasks), 1)
        generate.assert_not_called()

    def test_operator_generic_model_greeting_is_replaced_by_state_answer(self) -> None:
        target = self.runtime.register_target(
            handle="example.test",
            profile=ScopeProfile.HACKERONE,
            assets=["example.test"],
            emit_event=False,
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Recon: http://example.test/",
                summary="HTTP probe returned 200 for http://example.test/.",
                source_ref="fixture://example-greeting",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.85,
                freshness=0.9,
                metadata={"kind": "recon_scan", "effective_url": "http://example.test/", "status_code": 200},
            )
        )
        with patch.object(
            self.runtime.ollama,
            "generate",
            return_value=OllamaResponse(model="deepseek-r1:8b", text="Hello! I'm here to help. How can I assist you today?"),
        ) as generate:
            response = self.app.dispatch(
                "POST",
                "/api/chat",
                json.dumps({"message": "Draft a concise operator note for example.test."}).encode("utf-8"),
            )

        payload = json.loads(response.body)
        chat = payload["result"]["chat"]

        self.assertEqual(response.status, 200)
        self.assertEqual(chat["model"], "deterministic-state")
        self.assertIn("**Facts**", chat["answer"]["body"])
        self.assertTrue(chat["answer"]["metadata"]["guardrail_replaced_model_output"])
        generate.assert_called_once()

    def test_operator_status_uses_state_derived_potential_paths_and_actions(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Web content discovery: pirate.htb",
                summary="Bounded web content discovery checked 2 base URL(s) and found no interesting paths.",
                source_ref="fixture://content",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.7,
                freshness=0.9,
                metadata={"kind": "web_content_discovery"},
            )
        )
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Windows service discovery: pirate.htb",
                summary="Observed Microsoft Windows SMB service evidence.",
                source_ref="fixture://windows-service",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.78,
                freshness=0.9,
                metadata={
                    "kind": "tcp_service_discovery",
                    "open_services": [{"port": 445, "service": "microsoft-ds", "product": "Microsoft Windows Server"}],
                },
            )
        )
        exploit_evidence = EvidenceRecord(
            target_id=target.id,
            type=EvidenceType.MODEL_REVIEW,
            title="Exploit research: pirate.htb",
            summary="Searchsploit research found 1 non-DoS candidate: Microsoft Active Directory LDAP Server - Username Enumeration.",
            source_ref="fixture://exploit-research",
            verification_status=VerificationStatus.PARTIAL,
            confidence=0.68,
            freshness=0.9,
            metadata={"kind": "exploit_research", "match_count": 1, "executes_pocs": False},
        )
        self.runtime.store.insert_evidence(exploit_evidence)
        self.runtime.store.insert_interest(
            Interest(
                target_id=target.id,
                title="PoC research candidates for gated synthesis",
                summary="Searchsploit returned non-DoS public exploit references.",
                evidence_refs=[exploit_evidence.id],
                status=InterestStatus.OPEN,
                confidence=0.7,
                metadata={"class": "exploit_research", "match_count": 1},
            )
        )

        response = self.app.dispatch(
            "POST",
            "/api/chat",
            json.dumps({"message": "status and next step", "target": "pirate.htb"}).encode("utf-8"),
        )
        answer = json.loads(response.body)["result"]["chat"]["answer"]["body"]

        self.assertIn("**Potential Paths**", answer)
        self.assertIn("retained 1 non-DoS public exploit reference", answer)
        self.assertIn("Run gated public PoC applicability validation", answer)
        self.assertIn("Known username/password are not configured", answer)
        self.assertNotIn("Gated exploit-synthesis/adaptation primitive is missing", answer)
        self.assertNotIn("Add a bounded web content discovery primitive", answer)
        self.assertNotIn("No verified findings are stored for this target.", answer)

    def test_work_status_explains_idle_blockers(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.MODEL_REVIEW,
                title="Exploit research: pirate.htb",
                summary="Searchsploit research found 1 non-DoS candidate.",
                source_ref="fixture://exploit-research",
                verification_status=VerificationStatus.PARTIAL,
                confidence=0.68,
                freshness=0.9,
                metadata={"kind": "exploit_research", "match_count": 1, "executes_pocs": False},
            )
        )

        payload = self.runtime.work_status_payload()

        self.assertIn("blockers", payload)
        self.assertTrue(payload["blockers"])
        self.assertIn("PoC candidates", payload["summary"])

__all__ = ["WebConsoleTestsPart10"]
