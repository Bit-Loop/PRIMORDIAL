from __future__ import annotations

from tests.test_runtime_integration_common import *


class RuntimeIntegrationTestsPart5(RuntimeIntegrationTestsBase):
    def test_kerberos_user_discovery_normalizes_ldap_principals(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
                root,
                targets=[
                    {
                        "handle": "pirate.htb",
                        "display_name": "Pirate Fixture",
                        "in_scope": True,
                        "assets": [{"asset": PIRATE_IP, "asset_type": "ip"}],
                    }
                ],
            )
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)
            target = runtime.store.list_targets()[0]
            runtime.store.insert_evidence(
                EvidenceRecord(
                    target_id=target.id,
                    type=EvidenceType.TOOL_OUTPUT,
                    title="AD enumeration",
                    summary="RootDSE observed.",
                    source_ref="fixture://ad",
                    verification_status=VerificationStatus.VERIFIED,
                    confidence=0.8,
                    freshness=0.9,
                    metadata={
                        "kind": "ad_enumeration",
                        "ldap_rootdse": {"defaultNamingContext": ["DC=pirate,DC=htb"]},
                    },
                )
            )
            task = Task(
                target_id=target.id,
                phase=MethodologyPhase.RECON,
                kind=TaskKind.KERBEROS_USER_DISCOVERY,
                title="Run Kerberos user discovery",
                summary="Discover users.",
                role=AgentRole.RECON_WORKER,
            )

            def fake_command(_executor, *, tool: str, argv: list[str], timeout_seconds: int) -> dict[str, object]:
                stdout = ""
                if tool == "ldapsearch":
                    stdout = (
                        "dn: CN=Anne Bonny,CN=Users,DC=pirate,DC=htb\n"
                        "sAMAccountName: anne\n"
                        "userPrincipalName: anne@pirate.htb\n"
                        "servicePrincipalName: HTTP/pirate.htb\n\n"
                        "dn: CN=PIRATE$,CN=Computers,DC=pirate,DC=htb\n"
                        "sAMAccountName: PIRATE$\n\n"
                    )
                return {
                    "tool": tool,
                    "argv": argv,
                    "executed": True,
                    "returncode": 0,
                    "stdout": stdout,
                    "stderr": "",
                    "timeout": False,
                }

            with patch(
                "primordial.modes.security.execution.PrimitiveExecutor._run_host_command",
                autospec=True,
                side_effect=fake_command,
            ):
                result = runtime.executor.execute(task, None)

            self.assertTrue(result.success)
            self.assertEqual(result.evidence[0].metadata["kind"], "kerberos_user_discovery")
            self.assertEqual(result.evidence[0].metadata["users"][0]["username"], "anne")
            self.assertEqual(result.evidence[0].metadata["spn_candidates"][0]["spn"], "HTTP/pirate.htb")
            runtime.shutdown()

    def test_credentialed_access_uses_redacted_secret_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            scope_path = write_scope_file(
                root,
                targets=[
                    {
                        "handle": "pirate.htb",
                        "display_name": "Pirate Fixture",
                        "in_scope": True,
                        "assets": [{"asset": PIRATE_IP, "asset_type": "ip"}],
                    }
                ],
            )
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)
            runtime.set_operator_intent("htb_lab")
            runtime.set_lab_credentials(username=fixture_secret("anne"), password=fixture_secret("super-secret"), domain="PIRATE")
            target = runtime.store.list_targets()[0]
            task = Task(
                target_id=target.id,
                phase=MethodologyPhase.EXPLOITATION,
                kind=TaskKind.CREDENTIALED_ACCESS_CHECK,
                title="Verify credentialed access",
                summary="Check SMB/WinRM.",
                role=AgentRole.EXPLOITATION_WORKER,
            )

            def fake_secret_command(
                _executor,
                *,
                tool: str,
                argv: list[str],
                redacted_argv: list[str],
                timeout_seconds: int,
            ) -> dict[str, object]:
                self.assertNotIn("super-secret", " ".join(redacted_argv))
                if argv[-1].startswith("get "):
                    quoted = argv[-1].split('"')
                    if len(quoted) >= 4 and quoted[1].endswith("user.txt"):
                        Path(quoted[3]).write_text("HTB{user-fixture}\n", encoding="utf-8")
                return {
                    "tool": tool,
                    "argv": redacted_argv,
                    "executed": True,
                    "returncode": 0,
                    "stdout": "Disk|C$|Default share\nuser.txt",
                    "stderr": "",
                    "timeout": False,
                }

            with patch(
                "primordial.modes.security.execution.PrimitiveExecutor._run_secret_host_command",
                autospec=True,
                side_effect=fake_secret_command,
            ):
                result = runtime.executor.execute(task, None)

            serialized = json.dumps(result.evidence[0].as_payload())
            self.assertTrue(result.success)
            self.assertEqual(result.evidence[0].metadata["kind"], "credentialed_access_check")
            self.assertNotIn("super-secret", serialized)
            self.assertTrue(result.evidence[0].metadata["auth_results"][0]["valid"])
            self.assertEqual(result.evidence[0].metadata["flag_hits"][0]["value"], "HTB{user-fixture}")
            runtime.shutdown()

__all__ = ["RuntimeIntegrationTestsPart5"]
