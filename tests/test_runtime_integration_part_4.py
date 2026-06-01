from __future__ import annotations

from tests.test_runtime_integration_common import *


class RuntimeIntegrationTestsPart4(RuntimeIntegrationTestsBase):
    def test_poc_applicability_validation_is_read_only_and_prerequisite_aware(self) -> None:
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
            target = runtime.store.list_targets()[0]
            runtime.store.insert_evidence(
                EvidenceRecord(
                    target_id=target.id,
                    type=EvidenceType.TOOL_OUTPUT,
                    title="TCP service discovery",
                    summary="Observed IIS and AD services.",
                    source_ref="fixture://service",
                    verification_status=VerificationStatus.VERIFIED,
                    confidence=0.8,
                    freshness=0.9,
                    metadata={
                        "kind": "tcp_service_discovery",
                        "open_services": [
                            {"service": "http", "port": 80, "banner": "Microsoft-IIS/10.0"},
                            {"service": "ldap", "port": 389, "banner": ""},
                            {"service": "kerberos", "port": 88, "banner": ""},
                        ],
                    },
                )
            )
            research = EvidenceRecord(
                target_id=target.id,
                type=EvidenceType.MODEL_REVIEW,
                title="Exploit research: pirate.htb",
                summary=(
                    "Searchsploit research found 2 non-DoS candidate(s): "
                    "Microsoft Active Directory LDAP Server - Username Enumeration, "
                    "Microsoft Exchange Active Directory Topology - Unquoted Service Path."
                ),
                source_ref="fixture://exploit-research",
                verification_status=VerificationStatus.PARTIAL,
                confidence=0.68,
                freshness=0.9,
                metadata={"kind": "exploit_research", "match_count": 2, "executes_pocs": False},
            )
            runtime.store.insert_evidence(research)
            task = Task(
                target_id=target.id,
                phase=MethodologyPhase.ANALYSIS,
                kind=TaskKind.POC_APPLICABILITY_VALIDATION,
                title="Validate public PoC applicability",
                summary="Classify retained public PoCs.",
                role=AgentRole.CODE_WORKER,
            )

            result = runtime.executor.execute(task, None)

            self.assertTrue(result.success)
            self.assertEqual(result.evidence[0].metadata["kind"], "poc_applicability_validation")
            self.assertFalse(result.evidence[0].metadata["executes_pocs"])
            self.assertFalse(result.evidence[0].metadata["writes_exploit_code"])
            self.assertIn("No PoC was executed", result.notes[0].body)
            self.assertIn("requires user shell", result.notes[0].body)
            runtime.shutdown()

    def test_searchsploit_queries_are_versioned_and_do_not_use_raw_headers(self) -> None:
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
            runtime.set_operator_intent("htb_lab")
            runtime.import_scope(scope_path, ScopeProfile.HACK_THE_BOX)
            target = runtime.store.list_targets()[0]
            runtime.store.insert_evidence(
                EvidenceRecord(
                    target_id=target.id,
                    type=EvidenceType.HTTP_REPLAY,
                    title="HTTP probe",
                    summary="IIS default page",
                    source_ref="fixture://http",
                    verification_status=VerificationStatus.VERIFIED,
                    confidence=0.8,
                    freshness=0.9,
                    metadata={"headers": {"server": "Microsoft-IIS/10.0"}, "title": "IIS Windows Server"},
                )
            )
            runtime.store.insert_evidence(
                EvidenceRecord(
                    target_id=target.id,
                    type=EvidenceType.TOOL_OUTPUT,
                    title="TCP service discovery",
                    summary="Observed IIS headers and AD services.",
                    source_ref="fixture://service",
                    verification_status=VerificationStatus.VERIFIED,
                    confidence=0.8,
                    freshness=0.9,
                    metadata={
                        "kind": "tcp_service_discovery",
                        "open_services": [
                            {
                                "service": "http",
                                "port": 80,
                                "banner": (
                                    "HTTP/1.1 200 OK Content-Length: 703 Content-Type: text/html "
                                    "Last-Modified: Sun, Server: Microsoft-IIS/10.0"
                                ),
                            },
                            {"service": "ldap", "port": 389, "banner": ""},
                        ],
                    },
                )
            )

            queries = runtime.executor._build_searchsploit_queries(target.id)

            self.assertIn("Microsoft IIS 10.0", queries)
            self.assertIn("IIS 10.0", queries)
            self.assertIn("Active Directory LDAP", queries)
            self.assertNotIn("Microsoft IIS", queries)
            self.assertFalse(any(query.lower().startswith("http") for query in queries))
            self.assertFalse(any("content-length" in query.lower() for query in queries))
            runtime.shutdown()

    def test_searchsploit_refines_precise_queries_when_no_rows_return(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = AppConfig.from_env(project_root=root)
            config.manifests_dir = MANIFESTS_DIR
            config.ensure_directories()
            runtime = PrimordialRuntime(config)
            runtime.initialize()
            runtime.set_operator_intent("exploit_research_allowed")

            def fake_command(_executor, *, tool: str, argv: list[str], timeout_seconds: int) -> dict[str, object]:
                query = argv[-1]
                stdout = '{"RESULTS_EXPLOIT": [], "RESULTS_PAPER": []}'
                if query == "IIS 10.0":
                    stdout = (
                        '{"RESULTS_EXPLOIT": ['
                        '{"Title": "IIS 10.0 Remote Code Execution", "EDB-ID": "123", '
                        '"Path": "/usr/share/exploitdb/exploits/windows/remote/123.py", '
                        '"Type": "remote", "Platform": "windows"}'
                        '], "RESULTS_PAPER": []}'
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
                research = runtime.executor._run_searchsploit_research(["Microsoft IIS 10.0"])

            self.assertEqual(len(research["matches"]), 1)
            self.assertEqual(research["matches"][0]["query"], "IIS 10.0")
            refined = [item for item in research["command_results"] if item.get("refined_from")]
            self.assertTrue(refined)
            self.assertEqual(refined[-1]["refined_from"], "Microsoft IIS 10.0")
            runtime.shutdown()

__all__ = ["RuntimeIntegrationTestsPart4"]
