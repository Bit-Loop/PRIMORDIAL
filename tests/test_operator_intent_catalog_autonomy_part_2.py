from __future__ import annotations

from tests.test_operator_intent_catalog_autonomy_common import *


class OperatorIntentCatalogAutonomyTestsPart2(OperatorIntentCatalogAutonomyTestsBase):
    def test_htb_lab_intent_allows_exploit_research_planning(self) -> None:
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
        self.assertEqual(command.render_argv("/usr/bin/ldapsearch", {"target": {"host": INTERPOLATION_IP}})[0], "/usr/bin/ldapsearch")
        with self.assertRaises(CatalogValidationError):
            interpolate_argv(["{{ target.missing }}"], {"target": {"host": INTERPOLATION_IP}})

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

__all__ = ["OperatorIntentCatalogAutonomyTestsPart2"]
