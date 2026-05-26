from __future__ import annotations

import unittest

from primordial.labs.ctf import HardcodeScanner


class HardcodeScannerContractTests(unittest.TestCase):
    def test_hardcode_scanner_flags_raw_flags_target_ips_and_challenge_conditionals(self) -> None:
        result = HardcodeScanner.scan(
            {
                "solver.py": """
if target.name == "juice-shop-foundation":
    submit("ctf{hidden-answer}")
connect("10.10.10.42")
""",
                "README.txt": "General web enumeration checklist.",
            }
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(
            [finding.rule_id for finding in result.findings],
            ["raw_flag", "target_ip_literal", "challenge_specific_conditional"],
        )
        self.assertEqual(result.findings[0].path, "solver.py")

    def test_hardcode_scanner_passes_generalized_methodology(self) -> None:
        result = HardcodeScanner.scan(
            {
                "solver.py": """
if service.product == "magento":
    collect_version_evidence()
    propose_cve_precondition_check()
""",
            }
        )

        self.assertEqual(result.status, "pass")
        self.assertEqual(result.findings, ())

    def test_hardcode_scanner_flags_static_credential_literals(self) -> None:
        result = HardcodeScanner.scan(
            {
                "solver.py": """
username = "admin"
password = "Spring2026!"
login(username, password)
""",
            }
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["credential_literal", "credential_literal"])
        self.assertIn("credential", result.findings[0].message)

    def test_hardcode_scanner_flags_scripted_solve_command_chains(self) -> None:
        result = HardcodeScanner.scan(
            {
                "solver.py": """
run("nmap -sV target && gobuster dir -u http://target -w wordlist && curl http://target/admin")
""",
            }
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["scripted_command_chain"])
        self.assertIn("command chain", result.findings[0].message)

    def test_hardcode_scanner_flags_challenge_specific_path_literals(self) -> None:
        result = HardcodeScanner.scan(
            {
                "solver.py": """
path = "/administrator/secret-reset"
request(f"http://target{path}")
""",
            }
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["challenge_path_literal"])
        self.assertIn("path", result.findings[0].message)

    def test_hardcode_scanner_flags_challenge_specific_banner_literals(self) -> None:
        result = HardcodeScanner.scan(
            {
                "solver.py": """
if "SwagShop" in banner:
    run_known_box_route()
""",
            }
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["challenge_banner_literal"])
        self.assertIn("banner", result.findings[0].message)

    def test_hardcode_scanner_flags_static_service_port_assumptions(self) -> None:
        result = HardcodeScanner.scan(
            {
                "solver.py": """
target_port = 31337
probe_service(target_host, target_port)
""",
            }
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["static_service_port"])
        self.assertIn("port", result.findings[0].message)

    def test_hardcode_scanner_flags_challenge_specific_filename_literals(self) -> None:
        result = HardcodeScanner.scan(
            {
                "solver.py": """
payload_file = "swagshop_admin_backup.sql"
download_artifact(payload_file)
""",
            }
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["challenge_filename_literal"])
        self.assertIn("filename", result.findings[0].message)

    def test_hardcode_scanner_flags_hidden_solution_snippet_matches(self) -> None:
        result = HardcodeScanner.scan(
            {
                "solver.py": """
run_synthetic_fixture_shortcut(target)
""",
            },
            hidden_solution_snippets=("run_synthetic_fixture_shortcut(target)",),
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["hidden_solution_snippet"])
        self.assertIn("hidden solution", result.findings[0].message)

    def test_hardcode_scanner_flags_multiline_hidden_solution_snippet_matches(self) -> None:
        result = HardcodeScanner.scan(
            {
                "solver.py": """
prepare_fixture_shortcut()
execute_fixture_shortcut()
""",
            },
            hidden_solution_snippets=("prepare_fixture_shortcut()\nexecute_fixture_shortcut()",),
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["hidden_solution_snippet"])
        self.assertEqual(result.findings[0].line, 2)

    def test_hardcode_scanner_flags_similar_command_sequence_references(self) -> None:
        commands = (
            "discover synthetic host",
            "probe synthetic web",
            "enumerate synthetic route",
            "collect synthetic proof",
        )
        result = HardcodeScanner.scan(
            {
                "trace.txt": "\n".join(commands),
            },
            reference_command_sequences=(commands,),
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["command_sequence_similarity"])
        self.assertIn("command sequence", result.findings[0].message)

    def test_hardcode_scanner_flags_command_bigram_similarity_threshold(self) -> None:
        reference_commands = (
            "synthetic discover host",
            "synthetic probe web",
            "synthetic enumerate route",
            "synthetic inspect form",
            "synthetic capture token",
            "synthetic replay request",
            "synthetic parse response",
            "synthetic collect proof",
            "synthetic record evidence",
            "synthetic prepare report",
        )
        generated_commands = reference_commands[:-1]

        result = HardcodeScanner.scan(
            {
                "trace.txt": "\n".join(generated_commands),
            },
            reference_command_sequences=(reference_commands,),
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["command_sequence_similarity"])
        self.assertIn("bigram", result.findings[0].message)

    def test_hardcode_scanner_places_bigram_similarity_on_first_overlapping_command(self) -> None:
        reference_commands = (
            "synthetic discover host",
            "synthetic probe web",
            "synthetic enumerate route",
            "synthetic inspect form",
            "synthetic capture token",
            "synthetic replay request",
            "synthetic parse response",
            "synthetic collect proof",
            "synthetic record evidence",
            "synthetic prepare report",
        )
        generated_commands = ("synthetic unrelated warmup",) + reference_commands[1:]

        result = HardcodeScanner.scan(
            {
                "trace.txt": "\n".join(generated_commands),
            },
            reference_command_sequences=(reference_commands,),
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["command_sequence_similarity"])
        self.assertEqual(result.findings[0].line, 2)

    def test_hardcode_scanner_flags_normalized_text_span_similarity(self) -> None:
        reference_span = "Synthetic route collects proof, records evidence, and prepares a report"
        result = HardcodeScanner.scan(
            {
                "report.txt": "synthetic route collects proof records evidence and prepares a report",
            },
            reference_text_spans=(reference_span,),
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["text_span_similarity"])
        self.assertIn("text span", result.findings[0].message)

    def test_hardcode_scanner_flags_text_span_similarity_inside_longer_report(self) -> None:
        reference_span = "Synthetic route collects proof, records evidence, and prepares a report"
        report = """
general methodology starts with scoped evidence review and policy checks
synthetic route collects proof records evidence and prepares a report
follow up with generic validation notes and operator review
"""
        result = HardcodeScanner.scan(
            {
                "report.txt": report,
            },
            reference_text_spans=(reference_span,),
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["text_span_similarity"])
        self.assertEqual(result.findings[0].line, 3)

    def test_hardcode_scanner_places_text_span_similarity_on_matching_line(self) -> None:
        reference_span = "Synthetic route collects proof, records evidence, and prepares a report"
        report = """
synthetic setup notes stay generic before the suspicious span appears
operator review stays scoped and evidence-backed
synthetic route collects proof records evidence and prepares a report
"""
        result = HardcodeScanner.scan(
            {
                "report.txt": report,
            },
            reference_text_spans=(reference_span,),
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["text_span_similarity"])
        self.assertEqual(result.findings[0].line, 4)

    def test_hardcode_scanner_flags_code_simhash_similarity(self) -> None:
        reference_code = """
def synthetic_collect_route(target):
    response = fetch_route(target)
    proof = parse_proof(response)
    return record_evidence(proof)
"""
        generated_code = """
def synthetic_collect_route(target):
    response=fetch_route(target)
    proof=parse_proof(response)
    return record_evidence(proof)
"""
        result = HardcodeScanner.scan(
            {
                "solver.py": generated_code,
            },
            reference_code_spans=(reference_code,),
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["code_simhash_similarity"])
        self.assertIn("SimHash", result.findings[0].message)

    def test_hardcode_scanner_flags_code_simhash_similarity_inside_larger_file(self) -> None:
        reference_code = """
def synthetic_collect_route(target):
    response = fetch_route(target)
    proof = parse_proof(response)
    return record_evidence(proof)
"""
        generated_code = """
def unrelated_setup(config):
    return normalize_config(config)

def synthetic_collect_route(target):
    response=fetch_route(target)
    proof=parse_proof(response)
    return record_evidence(proof)

def unrelated_teardown(state):
    return close_state(state)
"""
        result = HardcodeScanner.scan(
            {
                "solver.py": generated_code,
            },
            reference_code_spans=(reference_code,),
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["code_simhash_similarity"])
        self.assertEqual(result.findings[0].line, 5)

    def test_hardcode_scanner_deduplicates_code_simhash_findings_for_same_location(self) -> None:
        reference_code = """
def synthetic_collect_route(target):
    response = fetch_route(target)
    proof = parse_proof(response)
    return record_evidence(proof)
"""
        generated_code = """
def synthetic_collect_route(target):
    response=fetch_route(target)
    proof=parse_proof(response)
    return record_evidence(proof)
"""
        result = HardcodeScanner.scan(
            {
                "solver.py": generated_code,
            },
            reference_code_spans=(reference_code, reference_code),
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual([finding.rule_id for finding in result.findings], ["code_simhash_similarity"])
        self.assertEqual(result.findings[0].line, 2)

    def test_hardcode_scanner_distinguishes_hard_fail_and_review_severity(self) -> None:
        reference_code = """
def synthetic_collect_route(target):
    response = fetch_route(target)
    proof = parse_proof(response)
    return record_evidence(proof)
"""
        result = HardcodeScanner.scan(
            {
                "flag.txt": "ctf{synthetic-hidden-answer}",
                "solver.py": """
def synthetic_collect_route(target):
    response=fetch_route(target)
    proof=parse_proof(response)
    return record_evidence(proof)
""",
            },
            reference_code_spans=(reference_code,),
        )

        self.assertEqual(result.status, "fail")
        severities = {finding.rule_id: finding.severity for finding in result.findings}
        self.assertEqual(severities["raw_flag"], "hard_fail")
        self.assertEqual(severities["code_simhash_similarity"], "review")


if __name__ == "__main__":
    unittest.main()
