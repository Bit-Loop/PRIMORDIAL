from __future__ import annotations

import subprocess

from tests.test_web_console_common import *


class WebConsoleTestsPart5(WebConsoleTestsBase):
    def test_ops_approval_buttons_resolve_credentialed_access_tasks(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        self.runtime.set_operator_intent("credential_validation")
        self.runtime.store.insert_evidence(self._windows_remote_access_evidence(target.id))
        approve_task = self._credentialed_access_approval_task(target.id)
        deny_task = self._credentialed_access_approval_task(target.id)
        self.runtime.store.insert_task(approve_task)
        self.runtime.store.insert_task(deny_task)

        control_response = self.app.dispatch("GET", "/api/control-plane")
        control_payload = json.loads(control_response.body)
        approval_ids = {item["task"] for item in control_payload["approvals"]}

        self.assertEqual(control_response.status, 200)
        self.assertIn(approve_task.id, approval_ids)
        self.assertIn(deny_task.id, approval_ids)

        with patch.object(self.runtime, "run_tick") as run_tick:
            approve_response = self.app.dispatch(
                "POST",
                "/api/actions/approve",
                json.dumps({"task_id": approve_task.id}).encode("utf-8"),
            )
        deny_response = self.app.dispatch(
            "POST",
            "/api/actions/deny",
            json.dumps({"task_id": deny_task.id}).encode("utf-8"),
        )
        approved = self.runtime.store.get_task(approve_task.id)
        denied = self.runtime.store.get_task(deny_task.id)

        self.assertEqual(approve_response.status, 200)
        self.assertEqual(deny_response.status, 200)
        self.assertIsNotNone(approved)
        self.assertIsNotNone(denied)
        assert approved is not None
        assert denied is not None
        self.assertEqual(approved.status, TaskStatus.PENDING)
        self.assertFalse(approved.requires_approval)
        self.assertEqual(denied.status, TaskStatus.CANCELLED)
        run_tick.assert_called_once_with(max_executions=1)

    def _windows_remote_access_evidence(self, target_id: str) -> EvidenceRecord:
        return EvidenceRecord(
            target_id=target_id,
            type=EvidenceType.TOOL_OUTPUT,
            title="Windows remote access services",
            summary="Observed Microsoft Windows SMB and WinRM surfaces.",
            source_ref="fixture://windows-remote-access",
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.86,
            freshness=0.9,
            metadata={
                "kind": "tcp_service_discovery",
                "open_services": [
                    {"port": 445, "service": "microsoft-ds", "product": "Microsoft Windows Server 2019"},
                    {"port": 5985, "service": "winrm", "product": "Microsoft HTTPAPI httpd"},
                ],
            },
        )

    def _credentialed_access_approval_task(self, target_id: str) -> Task:
        return Task(
            target_id=target_id,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.CREDENTIALED_ACCESS_CHECK,
            title="Verify credentialed SMB/WinRM access",
            summary="Use configured known credentials to verify access for pirate.htb.",
            role=AgentRole.EXPLOITATION_WORKER,
            risk_tier=RiskTier.HIGH,
            status=TaskStatus.NEEDS_APPROVAL,
            requires_approval=True,
        )

    def test_approval_inquiry_answers_from_task_and_evidence(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        evidence = EvidenceRecord(
            target_id=target.id,
            type=EvidenceType.TOOL_OUTPUT,
            title="HTTP header evidence",
            summary="HTTP service responded with a bounded banner capture.",
            source_ref="fixture://http-headers",
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.88,
            freshness=0.9,
            metadata={"kind": "http_probe"},
        )
        self.runtime.store.insert_evidence(evidence)
        task = Task(
            target_id=target.id,
            phase=MethodologyPhase.RECON,
            kind=TaskKind.RECON_SCAN,
            title="HTTP Header Analysis and Parameter Discovery",
            summary="Review HTTP headers before proposing any follow-up.",
            role=AgentRole.RECON_WORKER,
            risk_tier=RiskTier.LOW,
            status=TaskStatus.NEEDS_APPROVAL,
            requires_approval=True,
            evidence_refs=[evidence.id],
            metadata={"primitive_hint": "http-probe"},
        )
        self.runtime.store.insert_task(task)

        exact_response = self.app.dispatch(
            "POST",
            "/api/approvals/inquiry",
            json.dumps({"task_id": task.id, "message": "show me the exact request"}).encode("utf-8"),
        )
        evidence_response = self.app.dispatch(
            "POST",
            "/api/approvals/inquiry",
            json.dumps({"task_id": task.id, "message": "what evidence backs this?"}).encode("utf-8"),
        )

        exact = json.loads(exact_response.body)["result"]["chat"]["answer"]["body"]
        backed = json.loads(evidence_response.body)["result"]["chat"]["answer"]["body"]
        stored = self.runtime.store.get_task(task.id)

        self.assertEqual(exact_response.status, 200)
        self.assertEqual(evidence_response.status, 200)
        self.assertIn("**Approval Request**", exact)
        self.assertIn(task.id, exact)
        self.assertIn("`http-probe`", exact)
        self.assertNotIn("Approval note recorded locally", exact)
        self.assertIn("**Evidence Check**", backed)
        self.assertIn(evidence.id, backed)
        self.assertEqual(stored.status, TaskStatus.NEEDS_APPROVAL)

    def test_operator_next_steps_do_not_use_searchsploit_without_versioned_evidence(self) -> None:
        target = self.runtime.store.get_target_by_handle("pirate.htb")
        self.assertIsNotNone(target)
        assert target is not None
        self.runtime.store.insert_evidence(
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="TCP service discovery",
                summary="TCP connect checks completed; no service versions were identified.",
                source_ref="fixture://tcp-discovery",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.7,
                freshness=0.9,
                metadata={"kind": "tcp_service_discovery", "open_services": []},
            )
        )

        answer = self.runtime.ask_operator_ai("next 3 scoped recon steps", target=target.handle)["answer"]["body"]

        self.assertNotIn("Run evidence-backed Searchsploit research", answer)
        self.assertIn("Collect current service/version evidence before Searchsploit research", answer)

    def test_generated_web_bundle_has_no_fixture_switch_or_payload(self) -> None:
        generated_path = Path("primordial/core/web/frontend/src/generated-gui.jsx")
        if not generated_path.exists():
            subprocess.run(["node", "scripts/build-gui.mjs"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        generated = generated_path.read_text(encoding="utf-8")
        static_assets = Path("primordial/core/web/static/assets")
        bundle_text = "\n".join(path.read_text(encoding="utf-8") for path in static_assets.glob("*.js"))
        forbidden = [
            "PD_" + "DE" + "MO_DATA",
            "de" + "mo=1",
            ">DE" + "MO<",
            "window.PD_" + "DE" + "MO_DATA",
            "dom_pirate",
            "14:02:11",
            "fake live sparklines",
            "https://cdn.jsdelivr.net/npm/world-atlas",
            "target.local",
            "example.htb",
            "mock-pirate",
        ]

        for text in (generated, bundle_text):
            for token in forbidden:
                self.assertNotIn(token, text)
            for token in [
                "Target scope editor",
                "Target / domain",
                "Current IP",
                "Scope profile",
                "ADVANCED ASSETS",
                "Operator Intent still gates actions",
                "/api/runtime-control",
                "/api/credentials",
                "/api/integrations/caido",
                "http://127.0.0.1:8650/graphql",
                "AUTH FAILED",
                "HEALTH CHECK",
                "Health OK",
                "refreshCredentials",
                "refreshCaido",
                "auth-blocked",
                "USE TARGET SCOPE",
                "NO LIVE CAIDO TRAFFIC FOR CURRENT FILTER",
                "IMPORTED CAPTURES",
                "SEED TARGET GET",
                "SAVE CREDENTIALS",
                "Stored credentials",
                "Claude/GPT",
                "agent_chat_api wrapper",
                "remote_premium_local_wrapper",
                "Answer Citations",
                "READABLE",
                "RAW",
                "Evaluation Probes",
                "CVE/Vuln Sync",
                "Vulnerability Intel",
                "/api/rag/status",
                "/api/rag/search",
                "/api/rag/synthesize",
                "/api/rag/vuln/status",
                "/api/rag/vuln/sync",
                "/api/rag/vuln/search",
            ]:
                self.assertIn(token, text)
            self.assertNotIn("pirate.htb scope", text)
            self.assertNotIn("http://127.0.0.1:8080/graphql", text)
            self.assertNotIn("live_metrics=1", text)
            self.assertNotIn("FULL_REFRESH_MS", text)
        self.assertIn("aria-label={`Edit ${activeCredentialGroup.n} ${label}`}", generated)
        self.assertIn("runtimeDraftDirty", generated)
        self.assertIn("aria-label", bundle_text)
        self.assertNotIn("'integrations', 'credentials'", generated)
        self.assertNotIn("dangerouslySetInnerHTML", generated)

__all__ = ["WebConsoleTestsPart5"]
