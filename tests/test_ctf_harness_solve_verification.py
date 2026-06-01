from __future__ import annotations

import unittest

from primordial.labs.ctf import SolveSession, SolveVerifier


class SolveVerifierContractTests(unittest.TestCase):
    def test_solve_verifier_accepts_evidence_backed_policy_allowed_hardcode_clean_solve(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="ctf_solve_assisted",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )
        session = session.record_policy_decision(
            decision_id="policy:allow-http",
            action="http_probe",
            decision="allowed",
        )
        session = session.record_action(
            action_id="action:http-title",
            action_type="http_probe",
            status="completed",
            evidence_ids=["evidence:http-title"],
        )
        session = session.complete(result="solved", solve_status="solved")

        result = SolveVerifier.verify(
            session=session,
            hardcode_scan_result={"status": "pass"},
            hidden_solution_access_status="not_available_to_agent",
        )

        self.assertEqual(result.status, "pass")
        self.assertEqual(result.errors, ())

    def test_solve_verifier_rejects_solve_without_action_policy_or_clean_hardcode_scan(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="ctf_solve_assisted",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )
        session = session.record_action(
            action_id="action:bare-evidence",
            action_type="manual_claim",
            status="completed",
            evidence_ids=["evidence:bare-claim"],
        )
        session = session.complete(result="solved", solve_status="solved")

        result = SolveVerifier.verify(
            session=session,
            hardcode_scan_result={"status": "fail"},
            hidden_solution_access_status="available_to_agent",
        )

        self.assertEqual(result.status, "fail")
        self.assertIn("allowed policy decision", result.errors)
        self.assertIn("passing hardcode scan", result.errors)
        self.assertIn("hidden solution material", result.errors)

    def test_solve_verifier_routes_review_findings_without_hard_fail(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="ctf_solve_assisted",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )
        session = session.record_policy_decision(
            decision_id="policy:allow-http",
            action="http_probe",
            decision="allowed",
        )
        session = session.record_action(
            action_id="action:http-title",
            action_type="http_probe",
            status="completed",
            evidence_ids=["evidence:http-title"],
        )
        session = session.complete(result="solved", solve_status="solved")

        result = SolveVerifier.verify(
            session=session,
            hardcode_scan_result={
                "status": "fail",
                "findings": (
                    {
                        "rule_id": "code_simhash_similarity",
                        "path": "solver.py",
                        "line": 2,
                        "severity": "review",
                    },
                ),
            },
            hidden_solution_access_status="not_available_to_agent",
        )

        self.assertEqual(result.status, "review")
        self.assertEqual(result.errors, ("hardcode review finding",))


if __name__ == "__main__":
    unittest.main()
