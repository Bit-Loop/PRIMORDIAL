from __future__ import annotations

from tests.test_runtime_integration_common import *


class RuntimeIntegrationTestsPart3(RuntimeIntegrationTestsBase):
    def test_service_discovery_creates_evidence_without_shelling_out(self) -> None:
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
                        "assets": [
                            {"asset": "pirate.htb", "asset_type": "hostname"},
                            {"asset": PIRATE_IP, "asset_type": "ip"},
                        ],
                    }
                ],
            )
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)

            fake_scan = {
                "open_services": [
                    {
                        "host": PIRATE_IP,
                        "port": 22,
                        "service": "ssh",
                        "banner": "SSH-2.0-OpenSSH",
                        "source_asset": PIRATE_IP,
                    }
                ],
                "closed_count": 37,
                "errors": [],
            }
            with patch(
                "primordial.modes.security.execution.PrimitiveExecutor._probe_url",
                autospec=True,
                side_effect=lambda _executor, **kwargs: build_probe_fixture(kwargs["url"]),
            ), patch(
                "primordial.modes.security.execution.PrimitiveExecutor._scan_tcp_services",
                autospec=True,
                return_value=fake_scan,
            ):
                runtime.run_tick(max_executions=2)

            service_evidence = [
                item
                for item in runtime.store.list_evidence(limit=100)
                if item.metadata.get("kind") == "tcp_service_discovery"
            ]
            self.assertEqual(len(service_evidence), 1)
            self.assertEqual(service_evidence[0].metadata["open_services"][0]["service"], "ssh")
            self.assertTrue(runtime.store.list_interests(target_id=runtime.store.list_targets()[0].id, limit=10))
            runtime.shutdown()

    def test_ad_enumeration_normalizes_host_tool_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = self._pirate_runtime(Path(temp_dir), include_hostname=True)
            self._run_ad_recon(runtime)
            self._assert_ad_evidence(runtime)
            runtime.shutdown()

    def test_exploit_research_keeps_pocs_as_gated_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = self._pirate_runtime(Path(temp_dir), include_hostname=False)
            runtime.set_operator_intent("htb_lab")
            target = runtime.store.list_targets()[0]
            runtime.store.insert_evidence(self._iis_smb_evidence(target.id))
            task = Task(
                target_id=target.id,
                phase=MethodologyPhase.ANALYSIS,
                kind=TaskKind.EXPLOIT_RESEARCH,
                title="Research relevant public PoCs",
                summary="Search local exploit references.",
                role=AgentRole.CODE_WORKER,
            )
            with patch(
                "primordial.modes.security.execution.PrimitiveExecutor._run_searchsploit_research",
                autospec=True,
                return_value=self._fake_exploit_research(),
            ):
                result = runtime.executor.execute(task, None)

            self.assertTrue(result.success)
            self.assertEqual(result.evidence[0].metadata["kind"], "exploit_research")
            self.assertFalse(result.evidence[0].metadata["executes_pocs"])
            self.assertIn("No PoC was executed", result.notes[0].body)
            self.assertEqual(result.interests[0].metadata["class"], "exploit_research")
            self.assertEqual(result.notifications[0].channel, NotificationChannel.DISCORD)
            self.assertEqual(result.notifications[0].event_type, "poc_research_candidate")
            self.assertEqual(result.notifications[0].urgency, "high")
            self.assertIn("PoC research candidates found for pirate.htb", result.notifications[0].summary)
            self.assertFalse(result.notifications[0].metadata["executes_pocs"])
            runtime.shutdown()

    def _pirate_runtime(self, root: Path, *, include_hostname: bool) -> PrimordialRuntime:
        config = AppConfig.from_env(project_root=root)
        config.manifests_dir = MANIFESTS_DIR
        config.ensure_directories()
        assets = [{"asset": PIRATE_IP, "asset_type": "ip"}]
        if include_hostname:
            assets.insert(0, {"asset": "pirate.htb", "asset_type": "hostname"})
        scope_path = write_scope_file(
            root,
            targets=[{"handle": "pirate.htb", "display_name": "Pirate Fixture", "in_scope": True, "assets": assets}],
        )
        runtime = PrimordialRuntime(config)
        runtime.initialize()
        runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)
        return runtime

    def _run_ad_recon(self, runtime: PrimordialRuntime) -> None:
        with patch(
            "primordial.modes.security.execution.PrimitiveExecutor._probe_url",
            autospec=True,
            side_effect=lambda _executor, **kwargs: build_probe_fixture(kwargs["url"]),
        ), patch(
            "primordial.modes.security.execution.PrimitiveExecutor._scan_tcp_services",
            autospec=True,
            return_value=self._ad_service_scan(),
        ):
            runtime.run_tick(max_executions=2)
        with patch(
            "primordial.modes.security.execution.PrimitiveExecutor._run_host_command",
            autospec=True,
            side_effect=self._fake_ad_command,
        ), patch(
            "primordial.modes.security.execution.PrimitiveExecutor._run_dns_enumeration_commands",
            autospec=True,
            return_value=[],
        ), patch(
            "primordial.modes.security.execution.PrimitiveExecutor._run_web_content_discovery",
            autospec=True,
            return_value=[],
        ), patch(
            "primordial.modes.security.execution.PrimitiveExecutor._content_discovery_words",
            autospec=True,
            return_value=["admin"],
        ):
            runtime.run_tick(max_executions=3)

    def _ad_service_scan(self) -> dict[str, object]:
        return {
            "open_services": [
                {"host": PIRATE_IP, "port": 389, "service": "ldap", "banner": "", "source_asset": PIRATE_IP},
                {"host": PIRATE_IP, "port": 445, "service": "smb", "banner": "", "source_asset": PIRATE_IP},
            ],
            "closed_count": 36,
            "errors": [],
        }

    def _fake_ad_command(self, _executor, *, tool: str, argv: list[str], timeout_seconds: int) -> dict[str, object]:
        outputs = {
            "ldapsearch": "dn:\nnamingContexts: DC=pirate,DC=htb\ndefaultNamingContext: DC=pirate,DC=htb\n",
            "smbclient": "Disk|SYSVOL|Logon server share\nDisk|NETLOGON|Logon server share\nIPC|IPC$|IPC Service\n",
            "rpcclient": "user:[guest] rid:[0x1f5]\ngroup:[Domain Users] rid:[0x201]\n",
            "netexec": "",
        }
        return {
            "tool": tool,
            "argv": argv,
            "executed": True,
            "returncode": 0,
            "stdout": outputs.get(tool, ""),
            "stderr": "",
            "timeout": False,
        }

    def _assert_ad_evidence(self, runtime: PrimordialRuntime) -> None:
        ad_evidence = [
            item for item in runtime.store.list_evidence(limit=100) if item.metadata.get("kind") == "ad_enumeration"
        ]
        self.assertEqual(len(ad_evidence), 1)
        self.assertEqual(ad_evidence[0].metadata["ldap_rootdse"]["defaultNamingContext"], ["DC=pirate,DC=htb"])
        self.assertEqual(ad_evidence[0].metadata["smb_shares"][0]["name"], "IPC$")
        self.assertEqual(ad_evidence[0].metadata["rpc_users"][0]["name"], "guest")

    def _iis_smb_evidence(self, target_id: str) -> EvidenceRecord:
        return EvidenceRecord(
            target_id=target_id,
            type=EvidenceType.TOOL_OUTPUT,
            title="TCP service discovery",
            summary="Observed IIS and SMB services.",
            source_ref="fixture://service",
            verification_status=VerificationStatus.VERIFIED,
            confidence=0.8,
            freshness=0.9,
            metadata={
                "kind": "tcp_service_discovery",
                "open_services": [
                    {"service": "http", "port": 80, "banner": "Microsoft-IIS/10.0"},
                    {"service": "smb", "port": 445, "banner": ""},
                ],
            },
        )

    def _fake_exploit_research(self) -> dict[str, object]:
        return {
            "matches": [
                {
                    "query": "Microsoft IIS",
                    "section": "RESULTS_EXPLOIT",
                    "edb_id": "12345",
                    "title": "Microsoft IIS Example Remote Exploit",
                    "path": "/usr/share/exploitdb/exploits/windows/remote/12345.py",
                    "platform": "Windows",
                    "score": 8,
                }
            ],
            "suppressed_matches": [
                {
                    "query": "Microsoft IIS",
                    "edb_id": "99999",
                    "title": "Microsoft IIS Denial of Service",
                    "path": "/usr/share/exploitdb/exploits/windows/dos/99999.py",
                    "score": -5,
                }
            ],
            "examined_examples": [{"edb_id": "12345", "title": "Example", "excerpt": "print('poc')"}],
            "command_results": [],
        }

__all__ = ["RuntimeIntegrationTestsPart3"]
