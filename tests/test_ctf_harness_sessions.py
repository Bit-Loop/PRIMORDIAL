from __future__ import annotations

import unittest

from primordial.labs.ctf import SolveSession


class SolveSessionContractTests(unittest.TestCase):
    def test_solve_session_records_actions_evidence_blocks_policy_and_result(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="recon_only",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={"solver": "local_fast:v1"},
        )

        session = session.record_action(
            action_id="action:http-title",
            action_type="http_probe",
            status="completed",
            evidence_ids=["evidence:http-title"],
        )
        session = session.record_blocked_action(
            action_id="action:submit-flag",
            reason="recon_only blocks flag submission",
            policy_decision_id="policy:block-flag",
        )
        session = session.record_policy_decision(
            decision_id="policy:block-flag",
            action="ctfd_submit_flag",
            decision="blocked",
        )
        session = session.complete(result="no_solve", solve_status="blocked", report_ref="report:juice-1")

        self.assertEqual(session.evidence_ids, ("evidence:http-title",))
        self.assertEqual(session.actions[0]["action_id"], "action:http-title")
        self.assertEqual(session.blocked_actions[0]["policy_decision_id"], "policy:block-flag")
        self.assertEqual(session.policy_decisions[0]["decision"], "blocked")
        self.assertEqual(session.result, "no_solve")
        self.assertEqual(session.solve_status, "blocked")
        self.assertEqual(session.report_ref, "report:juice-1")

    def test_solve_session_blocks_flag_submission_under_recon_only(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="recon_only",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )

        with self.assertRaisesRegex(ValueError, "active intent"):
            session.record_flag_submission(
                challenge_id="juice-shop-foundation",
                captured_flag_ref="secret_ref:captured-flag",
                policy_decision_id="policy:allow-submit",
            )

    def test_solve_session_rejects_raw_flag_material_in_flag_submission_payload_before_intent_gate(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="recon_only",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )

        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            session.record_flag_submission(
                challenge_id="juice-shop-foundation",
                captured_flag_ref="ctf{training-only-hidden-value}",
                policy_decision_id="policy:allow-submit",
            )

    def test_solve_session_rejects_raw_flag_material_in_start_payload(self) -> None:
        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            SolveSession.start(
                id="solve-ctf{training-only-hidden-value}",
                target_id="juice-shop-foundation",
                engagement_profile="co_internal_lab",
                active_intent="recon_only",
                policy_version="policy:v1",
                code_version="git:abc123",
                model_versions={},
            )

    def test_solve_session_rejects_raw_flag_material_in_action_payload(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="recon_only",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )

        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            session.record_action(
                action_id="action-ctf{training-only-hidden-value}",
                action_type="http_probe",
                status="completed",
                evidence_ids=["evidence:http-title"],
            )

    def test_solve_session_rejects_non_evidence_refs_in_action_evidence_ids(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="recon_only",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )

        with self.assertRaisesRegex(ValueError, "evidence_ids entry"):
            session.record_action(
                action_id="action:http-title",
                action_type="http_probe",
                status="completed",
                evidence_ids=["note:operator-observation"],
            )

    def test_solve_session_rejects_blank_action_evidence_ids(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="recon_only",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )

        with self.assertRaisesRegex(ValueError, "evidence_ids entry"):
            session.record_action(
                action_id="action:http-title",
                action_type="http_probe",
                status="completed",
                evidence_ids=[""],
            )

    def test_solve_session_rejects_string_action_evidence_ids_container(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="recon_only",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )

        with self.assertRaisesRegex(ValueError, "evidence_ids must be a list or tuple"):
            session.record_action(
                action_id="action:http-title",
                action_type="http_probe",
                status="completed",
                evidence_ids="evidence:http-title",  # type: ignore[arg-type]
            )

    def test_solve_session_rejects_non_string_action_evidence_id_entries(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="recon_only",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )

        with self.assertRaisesRegex(ValueError, "evidence_ids entry must be a string"):
            session.record_action(
                action_id="action:http-title",
                action_type="http_probe",
                status="completed",
                evidence_ids=[1],  # type: ignore[list-item]
            )

    def test_solve_session_rejects_duplicate_action_evidence_ids(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="recon_only",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )

        with self.assertRaisesRegex(ValueError, "duplicate evidence_ids entry"):
            session.record_action(
                action_id="action:http-title",
                action_type="http_probe",
                status="completed",
                evidence_ids=["evidence:http-title", "evidence:http-title"],
            )

    def test_solve_session_rejects_raw_flag_material_in_blocked_action_payload(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="recon_only",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )

        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            session.record_blocked_action(
                action_id="action-ctf{training-only-hidden-value}",
                reason="recon_only blocks flag submission",
                policy_decision_id="policy:block-flag",
            )

    def test_solve_session_rejects_raw_flag_material_in_policy_decision_payload(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="recon_only",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )

        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            session.record_policy_decision(
                decision_id="policy-ctf{training-only-hidden-value}",
                action="ctfd_submit_flag",
                decision="blocked",
            )

    def test_solve_session_cannot_mark_solved_without_evidence(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="ctf_solve_assisted",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )

        with self.assertRaisesRegex(ValueError, "evidence"):
            session.complete(result="solved", solve_status="solved")

    def test_solve_session_rejects_raw_flag_material_in_completion_payload(self) -> None:
        session = SolveSession.start(
            id="solve-juice-1",
            target_id="juice-shop-foundation",
            engagement_profile="co_internal_lab",
            active_intent="recon_only",
            policy_version="policy:v1",
            code_version="git:abc123",
            model_versions={},
        )

        with self.assertRaisesRegex(ValueError, "hidden flag material"):
            session.complete(
                result="blocked after seeing ctf{training-only-hidden-value}",
                solve_status="blocked",
                report_ref="report:juice-1",
            )


if __name__ == "__main__":
    unittest.main()
