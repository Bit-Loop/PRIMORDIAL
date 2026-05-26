from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from primordial.config import AppConfig
from primordial.app.runtime import PrimordialRuntime
from primordial.core.autonomy import FailureDiagnosis, MethodologyCompiler, ScriptSafetyValidator, ToolInventory, ToolingGap, ToolingGapResolver
from primordial.core.autonomy.failure import FailureCategory
from primordial.core.autonomy.tools import GiveUpWithReason, ToolSubstitution
from primordial.core.catalog.capabilities import CapabilityCatalog
from primordial.core.catalog.interpolation import interpolate_argv
from primordial.core.catalog.loader import CatalogValidationError
from primordial.core.catalog.playbooks import PlaybookCatalog
from primordial.core.domain.enums import EvidenceType, ScopeProfile, VerificationStatus
from primordial.core.domain.enums import AgentRole, MethodologyPhase, TaskKind
from primordial.core.domain.models import EvidenceRecord, Target, Task
from primordial.core.intent.models import KerberosPolicy, OperatorIntentPolicy
from primordial.core.intent import OperatorIntentRegistry
from primordial.core.primitives.catalog import PrimitiveCatalog
from tests.support import write_scope_file


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFESTS_DIR = REPO_ROOT / "manifests"
CATALOG_DIR = REPO_ROOT / "catalog"


class OperatorIntentCatalogAutonomyTests(unittest.TestCase):
    def test_intent_registry_loads_and_rejects_unknown_fields(self) -> None:
        registry = OperatorIntentRegistry(CATALOG_DIR / "intents")
        intents = registry.load()
        self.assertIn("recon_only", {item.id for item in intents})
        self.assertFalse(registry.get("recon_only").policy.public_poc_research)
        htb_lab = registry.get("htb_lab").policy
        self.assertTrue(htb_lab.exploit_code_generation)
        self.assertTrue(htb_lab.poc_execution)
        self.assertTrue(htb_lab.credential_policy.credential_validation_allowed)
        self.assertTrue(htb_lab.credential_policy.credential_guessing_allowed)
        self.assertTrue(htb_lab.credential_policy.credential_spraying_allowed)
        self.assertTrue(htb_lab.credential_policy.hash_cracking_allowed)
        self.assertTrue(htb_lab.kerberos_policy.asrep_roast_check_allowed)
        self.assertTrue(htb_lab.kerberos_policy.kerberoast_check_allowed)
        self.assertTrue(htb_lab.lab_policy.lab_flag_collection_allowed)
        self.assertTrue(htb_lab.lab_policy.htb_lab_behavior_allowed)
        self.assertTrue(htb_lab.lab_policy.reverse_shell_allowed)
        local_ctf = registry.get("local_ctf_container").policy
        self.assertTrue(local_ctf.poc_execution)
        self.assertTrue(local_ctf.credential_policy.credential_validation_allowed)
        self.assertTrue(local_ctf.lab_policy.lab_flag_collection_allowed)
        self.assertFalse(local_ctf.public_poc_research)
        self.assertFalse(local_ctf.lab_policy.reverse_shell_allowed)
        ad_intent = registry.get("ad_lab")
        self.assertIn("In-House AD Attack Path", ad_intent.label)
        self.assertTrue(ad_intent.policy.kerberos_policy.asrep_roast_check_allowed)
        self.assertTrue(ad_intent.policy.kerberos_policy.kerberoast_check_allowed)
        self.assertFalse(ad_intent.policy.lab_policy.lab_flag_collection_allowed)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bad = root / "bad.yaml"
            bad.write_text(
                "id: bad\nlabel: Bad\ndescription: bad\nunknown: true\npolicy: {}\n",
                encoding="utf-8",
            )
            with self.assertRaises(CatalogValidationError):
                OperatorIntentRegistry(root).load()

    def test_kerberos_planning_records_only_allowed_split_checks(self) -> None:
        from primordial.core.orchestration.workflow import WorkflowOrchestrator

        class Store:
            def __init__(self, evidence: list[EvidenceRecord]) -> None:
                self.evidence = evidence
                self.events = []

            def list_evidence(self, target_id=None, limit: int = 200):
                return self.evidence

            def insert_target(self, target) -> None:
                self.target = target

            def insert_event(self, event) -> None:
                self.events.append(event)

        target = Target(
            handle="ad.internal",
            display_name="ad.internal",
            profile=ScopeProfile.HACKERONE,
        )
        evidence = [
            EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.TOOL_OUTPUT,
                title="Kerberos principals",
                summary="Discovered users and SPNs.",
                source_ref="fixture://kerberos-users",
                verification_status=VerificationStatus.VERIFIED,
                confidence=0.8,
                freshness=0.9,
                metadata={
                    "kind": "kerberos_user_discovery",
                    "users": [{"username": "alice"}],
                    "spn_candidates": [{"username": "svc_web", "spn": "HTTP/web.ad.internal"}],
                },
            )
        ]
        workflow = WorkflowOrchestrator.__new__(WorkflowOrchestrator)
        workflow.store = Store(evidence)
        workflow.active_intent_policy_loader = lambda: OperatorIntentPolicy(
            kerberos_policy=KerberosPolicy(asrep_roast_check_allowed=True, kerberoast_check_allowed=False)
        )
        workflow.active_intent_id_loader = lambda: "asrep_only_fixture"

        self.assertEqual(workflow._planned_kerberos_check_types(target), ["asrep_roast"])

    def test_kerberos_execution_enforces_split_flags(self) -> None:
        from primordial.modes.security.execution import PrimitiveExecutor

        executor = PrimitiveExecutor.__new__(PrimitiveExecutor)
        executor.active_intent_policy_loader = lambda: OperatorIntentPolicy(
            kerberos_policy=KerberosPolicy(asrep_roast_check_allowed=True, kerberoast_check_allowed=False)
        )
        executor.active_intent_id_loader = lambda: "asrep_only_fixture"
        task = Task(
            target_id=None,
            phase=MethodologyPhase.EXPLOITATION,
            kind=TaskKind.KERBEROS_ATTACK_CHECK,
            title="Kerberoast-only fixture",
            summary="Should be blocked because only AS-REP is allowed.",
            role=AgentRole.EXPLOITATION_WORKER,
            metadata={"kerberos_checks": ["kerberoast"]},
        )

        result = executor._require_intent(task)

        self.assertIsNotNone(result)
        self.assertFalse(result.success)
        self.assertIn("Kerberoast", result.error or "")

    def test_recon_only_blocks_research_heavy_planning(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.catalog_dir = CATALOG_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
                root,
                targets=[
                    {
                        "handle": "target.htb",
                        "display_name": "Target Fixture",
                        "in_scope": True,
                        "assets": [{"asset": "10.10.10.10", "asset_type": "ip"}],
                    }
                ],
            )
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)
            runtime.set_operator_intent("recon_only")
            target = runtime.store.list_targets()[0]
            runtime.store.insert_evidence(
                EvidenceRecord(
                    target_id=target.id,
                    type=EvidenceType.TOOL_OUTPUT,
                    title="TCP service discovery",
                    summary="Observed AD and HTTP services.",
                    source_ref="fixture://service",
                    verification_status=VerificationStatus.VERIFIED,
                    confidence=0.8,
                    freshness=0.9,
                    metadata={
                        "kind": "tcp_service_discovery",
                        "open_services": [
                            {"host": "10.10.10.10", "port": 80, "service": "http", "banner": "Microsoft-IIS/10.0"},
                            {"host": "10.10.10.10", "port": 88, "service": "kerberos", "banner": ""},
                            {"host": "10.10.10.10", "port": 445, "service": "smb", "banner": ""},
                        ],
                    },
                )
            )

            report = runtime.run_tick(max_executions=0)

            self.assertFalse(any(task.kind.value == "exploit_research" for task in report.created_tasks))
            blocked = [
                event
                for event in runtime.store.list_events(limit=100)
                if event.metadata.get("blocked_by_operator_intent")
            ]
            self.assertTrue(blocked)
            self.assertEqual(blocked[0].metadata["active_intent"], "recon_only")
            runtime.shutdown()

    def test_htb_profile_without_environment_proof_stays_recon_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.catalog_dir = CATALOG_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
                root,
                targets=[{"handle": "target.htb", "assets": [{"asset": "10.10.10.10", "asset_type": "ip"}]}],
            )
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)

            self.assertEqual(runtime.active_operator_intent().id, "recon_only")
            runtime.shutdown()

    def test_verified_htb_environment_defaults_to_htb_lab_intent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.catalog_dir = CATALOG_DIR
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope_payload(
                {
                    "profile": "hack_the_box",
                    "metadata": {
                        "environment_class": "platform_lab",
                        "environment_verified": True,
                    },
                    "targets": [
                        {
                            "handle": "target.htb",
                            "assets": [{"asset": "10.10.10.10", "asset_type": "ip"}],
                        }
                    ],
                },
                source_name="verified-htb-test",
            )

            self.assertEqual(runtime.active_operator_intent().id, "htb_lab")
            session = runtime.store.get_active_session()
            self.assertIsNotNone(session)
            classification = session.metadata["environment_classification"]  # type: ignore[index]
            self.assertEqual(classification["environment"], "platform_lab")
            self.assertTrue(classification["verified_lab"])
            self.assertTrue(classification["upgrade_applied"])
            runtime.shutdown()

    def test_verified_local_ctf_environment_defaults_to_local_container_intent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.catalog_dir = CATALOG_DIR
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope_payload(
                {
                    "profile": "co_internal_lab",
                    "lab_id": "training-juice-shop",
                    "provisioning": {"mode": "docker"},
                    "scope": {"assets": ["http://127.0.0.1:3000"]},
                    "targets": [
                        {
                            "handle": "training-juice-shop",
                            "assets": [{"asset": "http://127.0.0.1:3000", "asset_type": "webapp"}],
                        }
                    ],
                },
                source_name="verified-local-ctf-test",
            )

            self.assertEqual(runtime.active_operator_intent().id, "local_ctf_container")
            session = runtime.store.get_active_session()
            self.assertIsNotNone(session)
            classification = session.metadata["environment_classification"]  # type: ignore[index]
            self.assertEqual(classification["environment"], "local_ctf_container")
            self.assertTrue(classification["verified_lab"])
            self.assertTrue(classification["upgrade_applied"])
            runtime.shutdown()

    def test_htb_lab_intent_allows_exploit_research_planning(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.catalog_dir = CATALOG_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
                root,
                targets=[{"handle": "target.htb", "assets": [{"asset": "10.10.10.10", "asset_type": "ip"}]}],
            )
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)
            runtime.set_operator_intent("htb_lab")
            target = runtime.store.list_targets()[0]
            runtime.store.insert_evidence(
                EvidenceRecord(
                    target_id=target.id,
                    type=EvidenceType.TOOL_OUTPUT,
                    title="TCP service discovery",
                    summary="Observed IIS service.",
                    source_ref="fixture://service",
                    verification_status=VerificationStatus.VERIFIED,
                    confidence=0.8,
                    freshness=0.9,
                    metadata={"kind": "tcp_service_discovery", "open_services": [{"port": 80, "service": "http", "banner": "Microsoft-IIS/10.0"}]},
                )
            )

            report = runtime.run_tick(max_executions=0)

            self.assertTrue(any(task.kind.value == "exploit_research" for task in report.created_tasks))
            runtime.shutdown()

    def test_catalog_playbooks_capabilities_and_interpolation(self) -> None:
        playbooks = PlaybookCatalog(CATALOG_DIR / "playbooks")
        loaded = playbooks.load()
        self.assertTrue(any(item.id == "recon.ad_enumeration" for item in loaded))
        command = playbooks.get("recon.ad_enumeration").commands[0]  # type: ignore[union-attr]
        self.assertEqual(command.render_argv("/usr/bin/ldapsearch", {"target": {"host": "10.0.0.1"}})[0], "/usr/bin/ldapsearch")
        with self.assertRaises(CatalogValidationError):
            interpolate_argv(["{{ target.missing }}"], {"target": {"host": "10.0.0.1"}})

        capabilities = CapabilityCatalog(CATALOG_DIR / "capabilities" / "semantics.yaml")
        capabilities.load()
        self.assertEqual(capabilities.get("smb_share_enumeration").safe_substitutions, ["smbclient"])  # type: ignore[union-attr]

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bad = root / "bad.yaml"
            bad.write_text(
                "id: bad\ncommands:\n  - id: dup\n    capability: smb_share_enumeration\n    tool: smbclient\n    argv: [smbclient, -L]\n",
                encoding="utf-8",
            )
            with self.assertRaises(CatalogValidationError):
                PlaybookCatalog(root).load()

    def test_primitive_catalog_rejects_unknown_fields(self) -> None:
        catalog = PrimitiveCatalog()
        with self.assertRaises(CatalogValidationError):
            catalog._manifest_from_payload({"name": "bad", "unexpected": True})

    def test_tool_gap_failure_safety_and_methodology_scaffolding(self) -> None:
        inventory = ToolInventory(approved_executables=["smbclient"])
        registry = OperatorIntentRegistry(CATALOG_DIR / "intents")
        registry.load()
        with patch("shutil.which", side_effect=lambda name: f"/usr/bin/{name}" if name == "smbclient" else None):
            outcome = ToolingGapResolver(inventory).resolve(ToolingGap("smb_share_enumeration", "netexec", "missing"), registry.get("recon_only").policy)
        self.assertIsInstance(outcome, ToolSubstitution)
        give_up = ToolingGapResolver(ToolInventory()).resolve(ToolingGap("ldap_base_discovery", "ldapsearch", "missing"), registry.get("recon_only").policy)
        self.assertIsInstance(give_up, GiveUpWithReason)

        diagnosis = FailureDiagnosis()
        self.assertEqual(diagnosis.classify(stderr="tool not found").category, FailureCategory.MISSING_TOOL)
        self.assertEqual(diagnosis.classify(timeout=True).category, FailureCategory.TIMEOUT)
        self.assertEqual(diagnosis.classify(stderr="parse failed").category, FailureCategory.PARSER_FAILURE)
        self.assertEqual(diagnosis.classify(stderr="NT_STATUS_ACCESS_DENIED").category, FailureCategory.AUTHENTICATION_REQUIRED)

        validator = ScriptSafetyValidator()
        self.assertTrue(validator.validate("import json\ndef main(raw): return json.loads(raw)\n")[0])
        self.assertFalse(validator.validate("import subprocess\nsubprocess.run(['id'])\n")[0])
        self.assertFalse(validator.validate("eval('1+1')\n")[0])
        self.assertFalse(validator.validate("exec('x=1')\n")[0])

        proposal = MethodologyCompiler(Path("proposals/methodology")).compile_markdown("# Web Review\nSteps", name="web_review")
        self.assertEqual(proposal.kind, "methodology")
        self.assertTrue(proposal.generated_artifacts)
        self.assertIn("Strict catalog validation.", proposal.promotion_requirements)


if __name__ == "__main__":
    unittest.main()
