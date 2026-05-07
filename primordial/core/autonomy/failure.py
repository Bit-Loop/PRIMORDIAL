from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class FailureCategory(StrEnum):
    MISSING_TOOL = "missing_tool"
    TIMEOUT = "timeout"
    PARSER_FAILURE = "parser_failure"
    AUTHENTICATION_REQUIRED = "authentication_required"
    PROTOCOL_MISMATCH = "protocol_mismatch"
    POLICY_BLOCKED = "policy_blocked"
    SCOPE_BLOCKED = "scope_blocked"
    OPERATOR_INTENT_BLOCKED = "operator_intent_blocked"
    UNKNOWN = "unknown_failure"


@dataclass(slots=True, frozen=True)
class FailureDiagnosisResult:
    category: FailureCategory
    reason: str


class FailureDiagnosis:
    def classify(self, *, stderr: str = "", stdout: str = "", timeout: bool = False, metadata: dict[str, object] | None = None) -> FailureDiagnosisResult:
        metadata = metadata or {}
        joined = f"{stdout}\n{stderr}".lower()
        if metadata.get("blocked_by_operator_intent"):
            return FailureDiagnosisResult(FailureCategory.OPERATOR_INTENT_BLOCKED, "blocked by active operator intent")
        if metadata.get("policy_blocked"):
            return FailureDiagnosisResult(FailureCategory.POLICY_BLOCKED, "blocked by policy")
        if metadata.get("scope_blocked"):
            return FailureDiagnosisResult(FailureCategory.SCOPE_BLOCKED, "blocked by scope")
        if timeout or "timed out" in joined:
            return FailureDiagnosisResult(FailureCategory.TIMEOUT, "command timed out")
        if "tool not found" in joined or "no such file or directory" in joined:
            return FailureDiagnosisResult(FailureCategory.MISSING_TOOL, "required tool is missing")
        if "parse" in joined and ("error" in joined or "failed" in joined):
            return FailureDiagnosisResult(FailureCategory.PARSER_FAILURE, "parser failed")
        if any(term in joined for term in ("authentication failed", "access denied", "logon failure", "nt_status_access_denied")):
            return FailureDiagnosisResult(FailureCategory.AUTHENTICATION_REQUIRED, "authentication required or failed")
        if any(term in joined for term in ("protocol negotiation failed", "wrong version number", "connection reset by peer")):
            return FailureDiagnosisResult(FailureCategory.PROTOCOL_MISMATCH, "protocol mismatch")
        return FailureDiagnosisResult(FailureCategory.UNKNOWN, "unknown failure")
