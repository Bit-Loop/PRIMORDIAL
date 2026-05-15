from __future__ import annotations

from primordial_preprocess.classification import classify_record


def _record(filename: str) -> dict:
    return {"filename": filename, "relative_path": filename}


def test_classifies_owasp_asvs_as_normal_standard():
    classified = classify_record(_record("OWASP Application Security Verification Standard.pdf"))
    assert classified["authority_level"] == "official_standard"
    assert classified["planner_visibility"] == "normal"
    assert classified["risk_level"] == "safe_planning"


def test_classifies_kernel_exploitation_as_restricted():
    classified = classify_record(_record("A Guide to Kernel Exploitation.pdf"))
    assert classified["planner_visibility"] == "restricted"
    assert classified["requires_operator_approval"] is True


def test_classifies_temporary_researchgate_html_as_junk():
    classified = classify_record(_record("ResearchGate temporarily unavailable.html"))
    assert classified["authority_level"] == "junk"
    assert classified["planner_visibility"] == "disabled"
