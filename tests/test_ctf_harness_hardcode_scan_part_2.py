from __future__ import annotations

from tests.test_ctf_harness_hardcode_scan_common import *


class HardcodeScannerContractTestsPart2(HardcodeScannerContractTestsBase):
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
                "flag.txt": fixture_flag("synthetic-hidden-answer"),
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

__all__ = ["HardcodeScannerContractTestsPart2"]
