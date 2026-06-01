from __future__ import annotations

from tests.test_operator_intent_catalog_autonomy_common import *


class OperatorIntentCatalogAutonomyTestsPart1(OperatorIntentCatalogAutonomyTestsBase):
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
                        "assets": [{"asset": LAB_IP, "asset_type": "ip"}],
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
                            {"host": LAB_IP, "port": 80, "service": "http", "banner": "Microsoft-IIS/10.0"},
                            {"host": LAB_IP, "port": 88, "service": "kerberos", "banner": ""},
                            {"host": LAB_IP, "port": 445, "service": "smb", "banner": ""},
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
                targets=[{"handle": "target.htb", "assets": [{"asset": LAB_IP, "asset_type": "ip"}]}],
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
                            "assets": [{"asset": LAB_IP, "asset_type": "ip"}],
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

__all__ = ["OperatorIntentCatalogAutonomyTestsPart1"]
