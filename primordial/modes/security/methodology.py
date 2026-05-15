from __future__ import annotations

from dataclasses import dataclass

from primordial.core.domain.enums import AgentRole, MethodologyPhase, RiskTier, TaskKind


@dataclass(frozen=True, slots=True)
class TaskBlueprint:
    phase: MethodologyPhase
    role: AgentRole
    capabilities: tuple[str, ...]
    risk_tier: RiskTier
    default_priority: int
    max_attempts: int


DEFAULT_PHASE_ORDER = (
    MethodologyPhase.RECON,
    MethodologyPhase.COLLECTION,
    MethodologyPhase.ANALYSIS,
    MethodologyPhase.EXPLOITATION,
    MethodologyPhase.CHAINING,
    MethodologyPhase.BEHAVIOR_VERIFICATION,
    MethodologyPhase.MEMORY_MAINTENANCE,
    MethodologyPhase.NOTIFICATION,
    MethodologyPhase.ADMINISTRATION,
)


DEFAULT_BLUEPRINTS: dict[TaskKind, TaskBlueprint] = {
    TaskKind.RECON_SCAN: TaskBlueprint(
        phase=MethodologyPhase.RECON,
        role=AgentRole.RECON_WORKER,
        capabilities=("http-probe", "content-discovery"),
        risk_tier=RiskTier.LOW,
        default_priority=90,
        max_attempts=2,
    ),
    TaskKind.SERVICE_DISCOVERY: TaskBlueprint(
        phase=MethodologyPhase.RECON,
        role=AgentRole.RECON_WORKER,
        capabilities=("tcp-service-discovery", "service-identification"),
        risk_tier=RiskTier.LOW,
        default_priority=88,
        max_attempts=1,
    ),
    TaskKind.DNS_ENUMERATION: TaskBlueprint(
        phase=MethodologyPhase.RECON,
        role=AgentRole.RECON_WORKER,
        capabilities=("dns-enumeration", "service-identification"),
        risk_tier=RiskTier.LOW,
        default_priority=87,
        max_attempts=1,
    ),
    TaskKind.WEB_CONTENT_DISCOVERY: TaskBlueprint(
        phase=MethodologyPhase.RECON,
        role=AgentRole.RECON_WORKER,
        capabilities=("content-discovery", "path-enumeration"),
        risk_tier=RiskTier.MODERATE,
        default_priority=86,
        max_attempts=1,
    ),
    TaskKind.AD_ENUMERATION: TaskBlueprint(
        phase=MethodologyPhase.RECON,
        role=AgentRole.RECON_WORKER,
        capabilities=("ad-enumeration", "smb-enumeration", "ldap-enumeration"),
        risk_tier=RiskTier.MODERATE,
        default_priority=85,
        max_attempts=1,
    ),
    TaskKind.KERBEROS_USER_DISCOVERY: TaskBlueprint(
        phase=MethodologyPhase.RECON,
        role=AgentRole.RECON_WORKER,
        capabilities=("kerberos-user-discovery", "ldap-user-discovery", "principal-discovery"),
        risk_tier=RiskTier.MODERATE,
        default_priority=84,
        max_attempts=1,
    ),
    TaskKind.KERBEROS_ATTACK_CHECK: TaskBlueprint(
        phase=MethodologyPhase.ANALYSIS,
        role=AgentRole.EXPLOITATION_WORKER,
        capabilities=("asrep-roast-check", "kerberoast-check", "kerberos-attack-check"),
        risk_tier=RiskTier.HIGH,
        default_priority=76,
        max_attempts=1,
    ),
    TaskKind.CREDENTIALED_ACCESS_CHECK: TaskBlueprint(
        phase=MethodologyPhase.EXPLOITATION,
        role=AgentRole.EXPLOITATION_WORKER,
        capabilities=("credentialed-access-check", "smb-session", "winrm", "flag-collection"),
        risk_tier=RiskTier.HIGH,
        default_priority=74,
        max_attempts=1,
    ),
    TaskKind.EXPLOIT_RESEARCH: TaskBlueprint(
        phase=MethodologyPhase.ANALYSIS,
        role=AgentRole.CODE_WORKER,
        capabilities=("exploit-research", "searchsploit", "poc-analysis"),
        risk_tier=RiskTier.MODERATE,
        default_priority=78,
        max_attempts=1,
    ),
    TaskKind.POC_APPLICABILITY_VALIDATION: TaskBlueprint(
        phase=MethodologyPhase.ANALYSIS,
        role=AgentRole.CODE_WORKER,
        capabilities=("poc-applicability-validation", "poc-adaptation", "exploit-safety-review"),
        risk_tier=RiskTier.MODERATE,
        default_priority=77,
        max_attempts=1,
    ),
    TaskKind.ANALYZE_EVIDENCE: TaskBlueprint(
        phase=MethodologyPhase.ANALYSIS,
        role=AgentRole.ANALYSIS_WORKER,
        capabilities=("evidence-analysis", "hypothesis-generation"),
        risk_tier=RiskTier.MODERATE,
        default_priority=80,
        max_attempts=2,
    ),
    TaskKind.VERIFY_HYPOTHESIS: TaskBlueprint(
        phase=MethodologyPhase.EXPLOITATION,
        role=AgentRole.EXPLOITATION_WORKER,
        capabilities=("auth-analysis", "finding-verification"),
        risk_tier=RiskTier.HIGH,
        default_priority=70,
        max_attempts=2,
    ),
    TaskKind.CHAIN_CANDIDATES: TaskBlueprint(
        phase=MethodologyPhase.CHAINING,
        role=AgentRole.CHAINING_WORKER,
        capabilities=("chain-reasoning", "prerequisite-resolution"),
        risk_tier=RiskTier.HIGH,
        default_priority=60,
        max_attempts=2,
    ),
    TaskKind.VERIFY_AGENT_BEHAVIOR: TaskBlueprint(
        phase=MethodologyPhase.BEHAVIOR_VERIFICATION,
        role=AgentRole.BEHAVIOR_VERIFIER,
        capabilities=("trace-review", "loop-detection"),
        risk_tier=RiskTier.LOW,
        default_priority=75,
        max_attempts=1,
    ),
    TaskKind.COMPACT_MEMORY: TaskBlueprint(
        phase=MethodologyPhase.MEMORY_MAINTENANCE,
        role=AgentRole.MEMORY_WORKER,
        capabilities=("memory-compaction", "semantic-promotion"),
        risk_tier=RiskTier.LOW,
        default_priority=65,
        max_attempts=1,
    ),
    TaskKind.SYNC_NOTION: TaskBlueprint(
        phase=MethodologyPhase.NOTIFICATION,
        role=AgentRole.MEMORY_WORKER,
        capabilities=("notion-sync",),
        risk_tier=RiskTier.LOW,
        default_priority=40,
        max_attempts=1,
    ),
    TaskKind.SEND_NOTIFICATION: TaskBlueprint(
        phase=MethodologyPhase.NOTIFICATION,
        role=AgentRole.ORCHESTRATOR,
        capabilities=("discord-notify",),
        risk_tier=RiskTier.LOW,
        default_priority=30,
        max_attempts=1,
    ),
    TaskKind.REVIEW_PREMIUM_ESCALATION: TaskBlueprint(
        phase=MethodologyPhase.ANALYSIS,
        role=AgentRole.CLAUDE_REVIEWER,
        capabilities=("premium-review", "exploit-synthesis"),
        risk_tier=RiskTier.MODERATE,
        default_priority=68,
        max_attempts=1,
    ),
}


def blueprint_for(task_kind: TaskKind) -> TaskBlueprint:
    return DEFAULT_BLUEPRINTS[task_kind]
