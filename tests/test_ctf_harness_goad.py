from __future__ import annotations

from pathlib import Path
import unittest

from primordial.labs.ctf import (
    load_ctf_lab_phase_catalog,
    load_ctf_target_manifest,
    verify_goad_phase_controls,
    verify_local_ad_lab_environment,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "catalog" / "labs" / "ctf_lab_phases.yaml"


class CTFHarnessGOADTests(unittest.TestCase):
    def test_goad_controls_gate_kerberos_smb_and_operator_credentials(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(6)
        target = _goad_target()
        environment = verify_local_ad_lab_environment(
            target,
            domain="goad.local",
            observed_assets=["dc01.goad.local", "fileserver.goad.local"],
            evidence_refs=["evidence:goad-dc-health", "evidence:goad-reset-teardown"],
            reset_evidence_ref="evidence:goad-reset-teardown",
            profile="co_internal_lab",
            observations={"services": {"kerberos": 88, "smb": 445}},
        )

        result = verify_goad_phase_controls(
            phase,
            target,
            environment_proof=environment,
            allowed_actions=[
                {
                    "id": "kerberos-ticket-audit",
                    "target_id": target.id,
                    "protocol": "kerberos",
                    "asset": "dc01.goad.local",
                    "intent": "local_lab_validation",
                    "credential_ref": "operator:credential:goad-user",
                    "evidence_ids": ["evidence:goad-dc-health"],
                },
                {
                    "id": "smb-share-audit",
                    "target_id": target.id,
                    "protocol": "smb",
                    "asset": "fileserver.goad.local",
                    "intent": "local_lab_validation",
                    "credential_ref": "operator:credential:goad-user",
                    "evidence_ids": ["evidence:goad-dc-health"],
                },
            ],
            credential_material=[
                {
                    "id": "goad-user",
                    "target_id": target.id,
                    "source": "operator_supplied",
                    "credential_ref": "operator:credential:goad-user",
                    "evidence_ids": ["evidence:goad-dc-health"],
                }
            ],
        )

        self.assertEqual(result.target_id, "goad-light-local")
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.domain, "goad.local")
        self.assertEqual(result.action_ids, ("kerberos-ticket-audit", "smb-share-audit"))
        self.assertEqual(result.credential_ids, ("goad-user",))
        self.assertIn("kerberos_and_smb_actions_policy_gated", result.exit_gates)
        self.assertIn("credential_use_requires_operator_supplied_material", result.exit_gates)
        self.assertIn("evidence:goad-dc-health", result.evidence_refs)

    def test_goad_controls_reject_credentials_not_operator_supplied(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(6)
        target = _goad_target()
        environment = verify_local_ad_lab_environment(
            target,
            domain="goad.local",
            observed_assets=["dc01.goad.local", "fileserver.goad.local"],
            evidence_refs=["evidence:goad-dc-health", "evidence:goad-reset-teardown"],
            reset_evidence_ref="evidence:goad-reset-teardown",
            profile="co_internal_lab",
        )

        with self.assertRaisesRegex(ValueError, "operator_supplied"):
            verify_goad_phase_controls(
                phase,
                target,
                environment_proof=environment,
                allowed_actions=[
                    {
                        "id": "kerberos-ticket-audit",
                        "target_id": target.id,
                        "protocol": "kerberos",
                        "asset": "dc01.goad.local",
                        "intent": "local_lab_validation",
                        "credential_ref": "operator:credential:goad-user",
                        "evidence_ids": ["evidence:goad-dc-health"],
                    }
                ],
                credential_material=[
                    {
                        "id": "goad-user",
                        "target_id": target.id,
                        "source": "discovered",
                        "credential_ref": "operator:credential:goad-user",
                        "evidence_ids": ["evidence:goad-dc-health"],
                    }
                ],
            )

    def test_goad_controls_reject_actions_outside_lab_scope(self) -> None:
        phase = load_ctf_lab_phase_catalog(CATALOG_PATH).phase(6)
        target = _goad_target()
        environment = verify_local_ad_lab_environment(
            target,
            domain="goad.local",
            observed_assets=["dc01.goad.local", "fileserver.goad.local"],
            evidence_refs=["evidence:goad-dc-health", "evidence:goad-reset-teardown"],
            reset_evidence_ref="evidence:goad-reset-teardown",
            profile="co_internal_lab",
        )

        with self.assertRaisesRegex(ValueError, "lab scope"):
            verify_goad_phase_controls(
                phase,
                target,
                environment_proof=environment,
                allowed_actions=[
                    {
                        "id": "external-ldap-action",
                        "target_id": target.id,
                        "protocol": "ldap",
                        "asset": "ldap.example.com",
                        "intent": "local_lab_validation",
                        "credential_ref": "operator:credential:goad-user",
                        "evidence_ids": ["evidence:goad-dc-health"],
                    }
                ],
                credential_material=[
                    {
                        "id": "goad-user",
                        "target_id": target.id,
                        "source": "operator_supplied",
                        "credential_ref": "operator:credential:goad-user",
                        "evidence_ids": ["evidence:goad-dc-health"],
                    }
                ],
            )


def _goad_target():
    return load_ctf_target_manifest(
        {
            "lab_id": "goad-light-local",
            "title": "GOAD-Light Local AD Lab",
            "platform": "active_directory",
            "category": "active_directory",
            "difficulty": "advanced",
            "target_family": "goad_light",
            "source": {
                "repo_url": "https://github.com/Orange-Cyberdefense/GOAD",
                "path": "ad/GOAD-Light",
            },
            "scope": {
                "network": "goad.local",
                "assets": ["dc01.goad.local", "fileserver.goad.local"],
            },
            "provisioning": {
                "mode": "ad_lab",
                "network": "goad.local",
            },
            "evidence": {"required": ["domain_health", "service_inventory", "reset_teardown"]},
            "policy": {"default_intent": "recon_only"},
        }
    )


if __name__ == "__main__":
    unittest.main()
